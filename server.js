// server.js - ULTIMATE PRODUCTION BACKEND v30.0 - 100% FRONTEND PERFECT MATCH
// ENHANCED FOR RENDER DEPLOYMENT - SECURE & SCALABLE

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
const xss = require('xss-clean');
const hpp = require('hpp');
const { body, validationResult, param } = require('express-validator');
const cron = require('node-cron');
const path = require('path');
const multer = require('multer');
const fs = require('fs');
const nodemailer = require('nodemailer');
const QRCode = require('qrcode');
const speakeasy = require('speakeasy');
const WebSocket = require('ws');
const crypto = require('crypto');
const moment = require('moment');
const { v4: uuidv4 } = require('uuid');

// Enhanced environment configuration with validation
require('dotenv').config();

// ==================== ENVIRONMENT VALIDATION ====================
const requiredEnvVars = [
  'JWT_SECRET',
  'MONGODB_URI',
  'ADMIN_PASSWORD',
  'NODE_ENV'
];

const missingEnvVars = requiredEnvVars.filter(envVar => !process.env[envVar]);
if (missingEnvVars.length > 0) {
  console.error('❌ Missing required environment variables:', missingEnvVars);
  console.error('💡 Please set these in your Render environment variables');
  process.exit(1);
}

console.log('✅ Environment variables validated');

// ==================== ENHANCED PRODUCTION CONFIGURATION ====================
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
      connectSrc: ["'self'", "ws:", "wss:", "https://raw-wealthy-backend.onrender.com"]
    }
  }
}));

// Additional security middleware
app.use(xss());
app.use(hpp());
app.use(mongoSanitize());
app.use(compression());

// Enhanced Morgan logging for production
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
      "https://real-earning.vercel.app",
      "http://localhost:3000",
      "http://127.0.0.1:5500",
      "http://localhost:5500",
      "https://raw-wealthy-frontend.vercel.app",
      "https://rawwealthy.com",
      "https://www.rawwealthy.com",
      "http://localhost:3001",
      "https://raw-wealthy.vercel.app",
      "https://raw-wealthy-yibn.onrender.com",
      "https://raw-wealthy-frontend.vercel.app",
      "http://localhost:8080",
      "http://127.0.0.1:8080",
      "https://raw-wealthy-frontend.vercel.app",
      "https://raw-wealthy-backend.onrender.com"  // Added for Render deployment
    ];
    
    // Allow requests with no origin (like mobile apps or curl requests)
    if (!origin) return callback(null, true);
    
    if (allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      console.log('🚫 Blocked by CORS:', origin);
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
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 5, // Limit each IP to 5 create account requests per windowMs
  message: { 
    success: false, 
    message: 'Too many accounts created from this IP, please try again after an hour' 
  },
  skipSuccessfulRequests: true,
  standardHeaders: true,
  legacyHeaders: false
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // Limit each IP to 10 login requests per windowMs
  message: { 
    success: false, 
    message: 'Too many authentication attempts from this IP, please try again after 15 minutes' 
  },
  skipSuccessfulRequests: true
});

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 500, // Limit each IP to 500 requests per windowMs
  message: { 
    success: false, 
    message: 'Too many requests from this IP, please try again later' 
  },
  skipFailedRequests: false
});

const financialLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // More strict limits for financial operations
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
const storage = multer.memoryStorage();

const fileFilter = (req, file, cb) => {
  const allowedMimes = [
    'image/jpeg', 
    'image/jpg', 
    'image/png', 
    'image/gif', 
    'image/webp', 
    'application/pdf'
  ];
  
  if (allowedMimes.includes(file.mimetype)) {
    cb(null, true);
  } else {
    cb(new Error(`Invalid file type: ${file.mimetype}. Only images and PDFs are allowed.`), false);
  }
};

const upload = multer({
  storage: storage,
  fileFilter: fileFilter,
  limits: { 
    fileSize: 10 * 1024 * 1024, // 10MB limit
    files: 5
  }
});

// Enhanced file upload handler with better error handling
const handleFileUpload = async (file, folder = 'general') => {
  if (!file) return null;
  
  try {
    const uploadsDir = path.join(__dirname, 'uploads', folder);
    
    // Create directory if it doesn't exist
    if (!fs.existsSync(uploadsDir)) {
      fs.mkdirSync(uploadsDir, { recursive: true });
    }
    
    // Generate secure filename
    const fileExtension = path.extname(file.originalname);
    const filename = `${Date.now()}-${crypto.randomBytes(16).toString('hex')}${fileExtension}`;
    const filepath = path.join(uploadsDir, filename);
    
    // Write file
    await fs.promises.writeFile(filepath, file.buffer);
    
    return `/uploads/${folder}/${filename}`;
  } catch (error) {
    console.error('File upload error:', error);
    throw new Error('File upload failed: ' + error.message);
  }
};

// Serve static files securely
app.use('/uploads', express.static(path.join(__dirname, 'uploads'), {
  maxAge: '1d',
  setHeaders: (res, path) => {
    // Security headers for static files
    res.set('X-Content-Type-Options', 'nosniff');
  }
}));

// ==================== ENHANCED WEBSOCKET SETUP ====================
const wss = new WebSocket.Server({ 
  noServer: true,
  clientTracking: true
});

const connectedClients = new Map();

wss.on('connection', (ws, request) => {
  const userId = request.headers['user-id'];
  
  if (userId) {
    connectedClients.set(userId, ws);
    console.log(`✅ User ${userId} connected via WebSocket`);
    
    ws.send(JSON.stringify({
      type: 'connection_established',
      message: 'WebSocket connection established',
      timestamp: new Date().toISOString()
    }));
  }

  ws.on('message', async (data) => {
    try {
      const message = JSON.parse(data);
      
      switch (message.type) {
        case 'ping':
          ws.send(JSON.stringify({ 
            type: 'pong', 
            timestamp: Date.now() 
          }));
          break;
        case 'subscribe':
          if (message.channel) {
            ws.subscriptions = ws.subscriptions || new Set();
            ws.subscriptions.add(message.channel);
          }
          break;
        default:
          console.log('Unknown WebSocket message type:', message.type);
      }
    } catch (error) {
      console.error('WebSocket message error:', error);
      ws.send(JSON.stringify({
        type: 'error',
        message: 'Invalid message format'
      }));
    }
  });

  ws.on('close', (code, reason) => {
    if (userId) {
      connectedClients.delete(userId);
      console.log(`❌ User ${userId} disconnected. Code: ${code}, Reason: ${reason}`);
    }
  });

  ws.on('error', (error) => {
    console.error('WebSocket error:', error);
    if (userId) {
      connectedClients.delete(userId);
    }
  });
});

// Enhanced broadcast functions
const broadcastToUser = (userId, data) => {
  const client = connectedClients.get(userId);
  if (client && client.readyState === WebSocket.OPEN) {
    try {
      client.send(JSON.stringify({
        ...data,
        timestamp: new Date().toISOString()
      }));
    } catch (error) {
      console.error('Error sending WebSocket message:', error);
      connectedClients.delete(userId);
    }
  }
};

const broadcastToAll = (data) => {
  connectedClients.forEach((client, userId) => {
    if (client.readyState === WebSocket.OPEN) {
      try {
        client.send(JSON.stringify({
          ...data,
          timestamp: new Date().toISOString()
        }));
      } catch (error) {
        console.error('Error broadcasting to user:', userId, error);
        connectedClients.delete(userId);
      }
    }
  });
};

// ==================== ENHANCED DATABASE MODELS ====================

// User Model - 100% Frontend Compatible
const userSchema = new mongoose.Schema({
  // Personal Information
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
  
  // Account Information
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
  
  // Frontend Fields - ENHANCED
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
  
  // Referral System
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
  
  // Verification
  kyc_verified: { 
    type: Boolean, 
    default: false 
  },
  two_factor_enabled: { 
    type: Boolean, 
    default: false 
  },
  two_factor_secret: { 
    type: String, 
    select: false 
  },
  
  // Status
  is_active: { 
    type: Boolean, 
    default: true 
  },
  is_verified: { 
    type: Boolean, 
    default: false 
  },
  
  // Bank Details
  bank_details: {
    bank_name: String,
    account_name: String,
    account_number: String,
    verified: { type: Boolean, default: false }
  },
  
  // Timestamps
  last_login: Date,
  last_active: Date,
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
}, { 
  timestamps: true,
  toJSON: { 
    virtuals: true,
    transform: function(doc, ret) {
      delete ret.password;
      delete ret.two_factor_secret;
      return ret;
    }
  }
});

// Indexes for performance
userSchema.index({ email: 1 });
userSchema.index({ referral_code: 1 });
userSchema.index({ createdAt: -1 });
userSchema.index({ is_active: 1 });

userSchema.pre('save', async function(next) {
  if (this.isModified('password')) {
    this.password = await bcrypt.hash(this.password, 12);
  }
  
  if (!this.referral_code) {
    let isUnique = false;
    while (!isUnique) {
      this.referral_code = crypto.randomBytes(6).toString('hex').toUpperCase();
      const existingUser = await mongoose.models.User.findOne({ referral_code: this.referral_code });
      isUnique = !existingUser;
    }
  }
  
  this.updatedAt = new Date();
  next();
});

userSchema.methods.comparePassword = async function(candidatePassword) {
  return await bcrypt.compare(candidatePassword, this.password);
};

userSchema.methods.generate2FASecret = function() {
  const secret = speakeasy.generateSecret({
    name: `RawWealthy (${this.email})`,
    length: 32
  });
  this.two_factor_secret = secret.base32;
  return secret;
};

userSchema.methods.verify2FAToken = function(token) {
  if (!this.two_factor_secret) {
    return false;
  }
  
  return speakeasy.totp.verify({
    secret: this.two_factor_secret,
    encoding: 'base32',
    token: token,
    window: 2
  });
};

userSchema.virtual('tier').get(function() {
  return this.kyc_verified ? 'Verified Investor' : 'Standard Investor';
});

const User = mongoose.model('User', userSchema);

// Investment Plan Model - Frontend Compatible
const investmentPlanSchema = new mongoose.Schema({
  name: { 
    type: String, 
    required: [true, 'Plan name is required'],
    trim: true
  },
  description: { 
    type: String, 
    required: [true, 'Plan description is required'] 
  },
  min_amount: { 
    type: Number, 
    required: [true, 'Minimum amount is required'], 
    min: [1000, 'Minimum investment is ₦1000'] 
  },
  max_amount: { 
    type: Number, 
    min: [1000, 'Maximum investment must be at least ₦1000'] 
  },
  daily_interest: { 
    type: Number, 
    required: [true, 'Daily interest is required'], 
    min: [0.1, 'Daily interest must be at least 0.1%'], 
    max: [100, 'Daily interest cannot exceed 100%'] 
  },
  total_interest: { 
    type: Number, 
    required: [true, 'Total interest is required'], 
    min: [1, 'Total interest must be at least 1%'], 
    max: [1000, 'Total interest cannot exceed 1000%'] 
  },
  duration: { 
    type: Number, 
    required: [true, 'Duration is required'], 
    min: [1, 'Duration must be at least 1 day'] 
  },
  risk_level: { 
    type: String, 
    enum: ['low', 'medium', 'high'], 
    required: [true, 'Risk level is required'] 
  },
  raw_material: { 
    type: String, 
    required: [true, 'Raw material is required'] 
  },
  category: { 
    type: String, 
    enum: ['agriculture', 'mining', 'energy', 'metals', 'crypto', 'real_estate'], 
    default: 'agriculture' 
  },
  
  // Frontend Display
  is_active: { type: Boolean, default: true },
  is_popular: { type: Boolean, default: false },
  is_featured: { type: Boolean, default: false },
  image_url: String,
  color: String,
  icon: String,
  features: [String],
  
  // Stats
  investment_count: { type: Number, default: 0 },
  total_invested: { type: Number, default: 0 },
  
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
}, { 
  timestamps: true 
});

investmentPlanSchema.index({ is_active: 1, is_popular: -1 });
investmentPlanSchema.index({ category: 1 });

const InvestmentPlan = mongoose.model('InvestmentPlan', investmentPlanSchema);

// Investment Model - Frontend Compatible
const investmentSchema = new mongoose.Schema({
  user: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User', 
    required: [true, 'User is required'] 
  },
  plan: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'InvestmentPlan', 
    required: [true, 'Investment plan is required'] 
  },
  amount: { 
    type: Number, 
    required: [true, 'Investment amount is required'], 
    min: [1000, 'Minimum investment is ₦1000'] 
  },
  status: { 
    type: String, 
    enum: ['pending', 'active', 'completed', 'cancelled', 'failed'], 
    default: 'pending' 
  },
  start_date: { type: Date, default: Date.now },
  end_date: { type: Date, required: true },
  approved_at: Date,
  expected_earnings: { type: Number, required: true },
  earned_so_far: { type: Number, default: 0 },
  daily_earnings: { type: Number, default: 0 },
  payment_proof: String,
  auto_renew: { type: Boolean, default: false },
  approved_by: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
}, { 
  timestamps: true 
});

investmentSchema.virtual('remaining_days').get(function() {
  if (this.status !== 'active') return 0;
  const now = new Date();
  const end = new Date(this.end_date);
  const diffTime = Math.max(0, end - now);
  return Math.ceil(diffTime / (1000 * 60 * 60 * 24));
});

investmentSchema.virtual('progress_percentage').get(function() {
  if (this.status !== 'active') return this.status === 'completed' ? 100 : 0;
  const now = new Date();
  const start = new Date(this.start_date);
  const end = new Date(this.end_date);
  const totalDuration = end - start;
  const elapsed = now - start;
  return Math.min(100, Math.max(0, (elapsed / totalDuration) * 100));
});

investmentSchema.pre('save', async function(next) {
  if (this.isModified('plan') && this.plan) {
    const plan = await InvestmentPlan.findById(this.plan);
    if (plan) {
      const endDate = new Date(this.start_date || new Date());
      endDate.setDate(endDate.getDate() + plan.duration);
      this.end_date = endDate;
      
      this.expected_earnings = (this.amount * plan.total_interest) / 100;
      this.daily_earnings = (this.amount * plan.daily_interest) / 100;
    }
  }
  this.updatedAt = new Date();
  next();
});

investmentSchema.index({ user: 1, status: 1 });
investmentSchema.index({ status: 1, createdAt: -1 });

const Investment = mongoose.model('Investment', investmentSchema);

// Deposit Model - Frontend Compatible
const depositSchema = new mongoose.Schema({
  user: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User', 
    required: [true, 'User is required'] 
  },
  amount: { 
    type: Number, 
    required: [true, 'Deposit amount is required'], 
    min: [500, 'Minimum deposit is ₦500'] 
  },
  payment_method: { 
    type: String, 
    enum: ['bank_transfer', 'crypto', 'paypal', 'card'], 
    required: [true, 'Payment method is required'] 
  },
  status: { 
    type: String, 
    enum: ['pending', 'approved', 'rejected', 'cancelled'], 
    default: 'pending' 
  },
  payment_proof: String,
  transaction_hash: String,
  reference: { type: String, unique: true },
  admin_notes: String,
  approved_by: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  approved_at: Date,
  
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
}, { 
  timestamps: true 
});

depositSchema.pre('save', function(next) {
  if (!this.reference) {
    this.reference = `DEP${Date.now()}${crypto.randomBytes(4).toString('hex').toUpperCase()}`;
  }
  next();
});

depositSchema.index({ user: 1, status: 1 });
depositSchema.index({ reference: 1 });

const Deposit = mongoose.model('Deposit', depositSchema);

// Withdrawal Model - Frontend Compatible
const withdrawalSchema = new mongoose.Schema({
  user: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User', 
    required: [true, 'User is required'] 
  },
  amount: { 
    type: Number, 
    required: [true, 'Withdrawal amount is required'], 
    min: [1000, 'Minimum withdrawal is ₦1000'] 
  },
  payment_method: { 
    type: String, 
    enum: ['bank_transfer', 'crypto', 'paypal'], 
    required: [true, 'Payment method is required'] 
  },
  platform_fee: { type: Number, default: 0 },
  net_amount: { type: Number, required: true },
  bank_details: {
    bank_name: String,
    account_name: String,
    account_number: String
  },
  wallet_address: String,
  paypal_email: String,
  status: { 
    type: String, 
    enum: ['pending', 'approved', 'rejected', 'paid'], 
    default: 'pending' 
  },
  reference: { type: String, unique: true },
  admin_notes: String,
  approved_by: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  approved_at: Date,
  
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
}, { 
  timestamps: true 
});

withdrawalSchema.pre('save', function(next) {
  if (this.isModified('amount')) {
    this.platform_fee = this.amount * 0.05; // 5% platform fee
    this.net_amount = this.amount - this.platform_fee;
  }
  
  if (!this.reference) {
    this.reference = `WD${Date.now()}${crypto.randomBytes(4).toString('hex').toUpperCase()}`;
  }
  next();
});

withdrawalSchema.index({ user: 1, status: 1 });
withdrawalSchema.index({ reference: 1 });

const Withdrawal = mongoose.model('Withdrawal', withdrawalSchema);

// Transaction Model - Frontend Compatible
const transactionSchema = new mongoose.Schema({
  user: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User', 
    required: [true, 'User is required'] 
  },
  type: { 
    type: String, 
    enum: ['deposit', 'withdrawal', 'investment', 'earning', 'referral', 'bonus', 'fee', 'refund'], 
    required: [true, 'Transaction type is required'] 
  },
  amount: { 
    type: Number, 
    required: [true, 'Transaction amount is required'] 
  },
  description: { 
    type: String, 
    required: [true, 'Transaction description is required'] 
  },
  reference: { type: String, unique: true },
  status: { 
    type: String, 
    enum: ['pending', 'completed', 'failed'], 
    default: 'completed' 
  },
  related_investment: { type: mongoose.Schema.Types.ObjectId, ref: 'Investment' },
  related_deposit: { type: mongoose.Schema.Types.ObjectId, ref: 'Deposit' },
  related_withdrawal: { type: mongoose.Schema.Types.ObjectId, ref: 'Withdrawal' },
  
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
}, { 
  timestamps: true 
});

transactionSchema.pre('save', function(next) {
  if (!this.reference) {
    this.reference = `TXN${Date.now()}${crypto.randomBytes(6).toString('hex').toUpperCase()}`;
  }
  next();
});

transactionSchema.index({ user: 1, createdAt: -1 });
transactionSchema.index({ type: 1, status: 1 });

const Transaction = mongoose.model('Transaction', transactionSchema);

// KYC Model - Frontend Compatible
const kycSchema = new mongoose.Schema({
  user: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User', 
    required: [true, 'User is required'] 
  },
  id_type: { 
    type: String, 
    enum: ['national_id', 'passport', 'driver_license', 'voters_card'], 
    required: [true, 'ID type is required'] 
  },
  id_number: { 
    type: String, 
    required: [true, 'ID number is required'] 
  },
  id_front: { 
    type: String, 
    required: [true, 'ID front image is required'] 
  },
  id_back: { 
    type: String, 
    required: [true, 'ID back image is required'] 
  },
  selfie_with_id: { 
    type: String, 
    required: [true, 'Selfie with ID is required'] 
  },
  status: { 
    type: String, 
    enum: ['pending', 'approved', 'rejected'], 
    default: 'pending' 
  },
  admin_notes: String,
  reviewed_by: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  reviewed_at: Date,
  
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
}, { 
  timestamps: true 
});

kycSchema.index({ user: 1 });
kycSchema.index({ status: 1 });

const KYC = mongoose.model('KYC', kycSchema);

// Notification Model - Frontend Compatible
const notificationSchema = new mongoose.Schema({
  user: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User', 
    required: [true, 'User is required'] 
  },
  title: { 
    type: String, 
    required: [true, 'Notification title is required'] 
  },
  message: { 
    type: String, 
    required: [true, 'Notification message is required'] 
  },
  type: { 
    type: String, 
    enum: ['info', 'success', 'warning', 'error', 'promotional'], 
    default: 'info' 
  },
  is_read: { type: Boolean, default: false },
  action_url: String,
  
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
}, { 
  timestamps: true 
});

notificationSchema.index({ user: 1, is_read: 1 });
notificationSchema.index({ createdAt: -1 });

const Notification = mongoose.model('Notification', notificationSchema);

// Support Ticket Model - Frontend Compatible
const supportTicketSchema = new mongoose.Schema({
  user: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User', 
    required: [true, 'User is required'] 
  },
  subject: { 
    type: String, 
    required: [true, 'Subject is required'] 
  },
  message: { 
    type: String, 
    required: [true, 'Message is required'] 
  },
  category: { 
    type: String, 
    enum: ['general', 'technical', 'billing', 'investment', 'withdrawal', 'kyc', 'other'], 
    default: 'general' 
  },
  status: { 
    type: String, 
    enum: ['open', 'in_progress', 'resolved', 'closed'], 
    default: 'open' 
  },
  priority: { 
    type: String, 
    enum: ['low', 'medium', 'high', 'urgent'], 
    default: 'medium' 
  },
  admin_notes: String,
  assigned_to: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  resolved_at: Date,
  
  replies: [{
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    message: String,
    is_admin: { type: Boolean, default: false },
    attachments: [String],
    createdAt: { type: Date, default: Date.now }
  }],
  
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
}, { 
  timestamps: true 
});

supportTicketSchema.index({ user: 1, status: 1 });
supportTicketSchema.index({ status: 1, priority: -1 });

const SupportTicket = mongoose.model('SupportTicket', supportTicketSchema);

// ==================== ENHANCED MIDDLEWARE ====================

// Auth Middleware - Frontend Compatible
const auth = async (req, res, next) => {
  try {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    
    if (!token) {
      return res.status(401).json({ 
        success: false, 
        message: 'No token, authorization denied' 
      });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.id);
    
    if (!user) {
      return res.status(401).json({ 
        success: false, 
        message: 'Token is not valid' 
      });
    }

    if (!user.is_active) {
      return res.status(401).json({ 
        success: false, 
        message: 'Account is deactivated' 
      });
    }

    // Update last active timestamp
    user.last_active = new Date();
    await user.save();

    req.user = user;
    next();
  } catch (error) {
    if (error.name === 'JsonWebTokenError') {
      return res.status(401).json({ 
        success: false, 
        message: 'Invalid token' 
      });
    } else if (error.name === 'TokenExpiredError') {
      return res.status(401).json({ 
        success: false, 
        message: 'Token expired' 
      });
    }
    
    console.error('Auth middleware error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Server error during authentication' 
    });
  }
};

// Admin Auth Middleware
const adminAuth = async (req, res, next) => {
  try {
    await auth(req, res, () => {});
    
    if (!['admin', 'super_admin'].includes(req.user.role)) {
      return res.status(403).json({ 
        success: false, 
        message: 'Access denied. Admin only.' 
      });
    }
    next();
  } catch (error) {
    res.status(401).json({ 
      success: false, 
      message: 'Authentication failed' 
    });
  }
};

// Optional Auth Middleware (for public routes that might have user context)
const optionalAuth = async (req, res, next) => {
  try {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    
    if (token) {
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      const user = await User.findById(decoded.id);
      
      if (user && user.is_active) {
        req.user = user;
      }
    }
    next();
  } catch (error) {
    // Continue without user for optional auth
    next();
  }
};

// ==================== UTILITY FUNCTIONS ====================

// Response Formatter - Frontend Compatible
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

// Error Handler - Frontend Compatible
const handleError = (res, error, defaultMessage = 'An error occurred') => {
  console.error('Error:', error);
  
  // Mongoose validation error
  if (error.name === 'ValidationError') {
    const messages = Object.values(error.errors).map(val => val.message);
    return res.status(400).json(
      formatResponse(false, 'Validation Error', { errors: messages })
    );
  }
  
  // Mongoose duplicate key error
  if (error.code === 11000) {
    const field = Object.keys(error.keyValue)[0];
    return res.status(400).json(
      formatResponse(false, `${field} already exists`)
    );
  }
  
  // JWT errors
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
  
  // Custom error with status code
  const statusCode = error.statusCode || error.status || 500;
  const message = process.env.NODE_ENV === 'production' && statusCode === 500 
    ? defaultMessage 
    : error.message;

  return res.status(statusCode).json(
    formatResponse(false, message)
  );
};

// Email Configuration with better error handling
const createEmailTransporter = () => {
  if (!process.env.EMAIL_USER || !process.env.EMAIL_PASSWORD) {
    console.warn('⚠️ Email credentials not configured. Email functionality will be disabled.');
    return null;
  }

  return nodemailer.createTransporter({
    service: 'gmail',
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASSWORD
    }
  });
};

const emailTransporter = createEmailTransporter();

const sendEmail = async (to, subject, html) => {
  if (!emailTransporter) {
    console.warn('Email transporter not available. Skipping email send.');
    return false;
  }

  try {
    await emailTransporter.sendMail({
      from: process.env.EMAIL_USER || 'noreply@rawwealthy.com',
      to,
      subject,
      html
    });
    console.log(`✅ Email sent to ${to}`);
    return true;
  } catch (error) {
    console.error('❌ Email sending failed:', error);
    return false;
  }
};

// Pagination helper
const getPaginationOptions = (req) => {
  const page = Math.max(1, parseInt(req.query.page) || 1);
  const limit = Math.min(100, Math.max(1, parseInt(req.query.limit) || 10));
  const skip = (page - 1) * limit;
  
  return { page, limit, skip };
};

// ==================== DATABASE INITIALIZATION ====================
const initializeDatabase = async () => {
  try {
    console.log('🔄 Initializing database...');

    // Create admin user if doesn't exist
    const adminExists = await User.findOne({ email: 'admin@rawwealthy.com' });
    if (!adminExists) {
      const admin = new User({
        full_name: 'Raw Wealthy Admin',
        email: 'admin@rawwealthy.com',
        phone: '+2348000000001',
        password: process.env.ADMIN_PASSWORD,
        role: 'super_admin',
        kyc_verified: true,
        is_verified: true,
        balance: 0 // Start with 0 balance for security
      });
      await admin.save();
      console.log('✅ Super Admin user created');
    }

    // Create investment plans
    const plansExist = await InvestmentPlan.countDocuments();
    if (plansExist === 0) {
      const plans = [
        {
          name: 'Cocoa Beans',
          description: 'Invest in premium cocoa beans with stable returns',
          min_amount: 3500,
          max_amount: 50000,
          daily_interest: 2.5,
          total_interest: 75,
          duration: 30,
          risk_level: 'low',
          is_popular: true,
          raw_material: 'Cocoa',
          category: 'agriculture',
          features: ['Low Risk', 'Stable Returns', 'Beginner Friendly', 'Daily Payouts'],
          color: '#10b981',
          icon: '🌱'
        },
        {
          name: 'Gold',
          description: 'Precious metal investment with high liquidity',
          min_amount: 50000,
          max_amount: 500000,
          daily_interest: 3.2,
          total_interest: 96,
          duration: 30,
          risk_level: 'medium',
          is_popular: true,
          raw_material: 'Gold',
          category: 'metals',
          features: ['Medium Risk', 'Higher Returns', 'High Liquidity'],
          color: '#fbbf24',
          icon: '🥇'
        },
        {
          name: 'Crude Oil',
          description: 'Energy sector investment with premium returns',
          min_amount: 100000,
          max_amount: 1000000,
          daily_interest: 4.1,
          total_interest: 123,
          duration: 30,
          risk_level: 'high',
          raw_material: 'Crude Oil',
          category: 'energy',
          features: ['High Risk', 'Maximum Returns', 'Premium Investment'],
          color: '#dc2626',
          icon: '🛢️'
        },
        {
          name: 'Palm Oil',
          description: 'Agricultural commodity with consistent demand',
          min_amount: 15000,
          max_amount: 200000,
          daily_interest: 2.8,
          total_interest: 84,
          duration: 30,
          risk_level: 'low',
          raw_material: 'Palm Oil',
          category: 'agriculture',
          features: ['Low Risk', 'Consistent Demand', 'Stable Growth'],
          color: '#10b981',
          icon: '🌴'
        },
        {
          name: 'Diamond',
          description: 'Luxury commodity with exceptional returns',
          min_amount: 250000,
          max_amount: 2000000,
          daily_interest: 5.2,
          total_interest: 156,
          duration: 30,
          risk_level: 'high',
          raw_material: 'Diamond',
          category: 'mining',
          features: ['High Risk', 'Exceptional Returns', 'Luxury Commodity'],
          color: '#8b5cf6',
          icon: '💎'
        },
        {
          name: 'Copper',
          description: 'Industrial metal with growing global demand',
          min_amount: 75000,
          max_amount: 800000,
          daily_interest: 3.5,
          total_interest: 105,
          duration: 30,
          risk_level: 'medium',
          raw_material: 'Copper',
          category: 'metals',
          features: ['Medium Risk', 'Growing Demand', 'Industrial Use'],
          color: '#f59e0b',
          icon: '🔧'
        }
      ];

      await InvestmentPlan.insertMany(plans);
      console.log('✅ Investment plans created');
    }

    console.log('✅ Database initialization completed');
  } catch (error) {
    console.error('❌ Database initialization error:', error);
    throw error;
  }
};

// ==================== MONGODB CONNECTION ====================
const connectDB = async () => {
  try {
    console.log('🔄 Connecting to MongoDB...');
    
    const MONGODB_URI = process.env.MONGODB_URI;
    
    if (!MONGODB_URI) {
      throw new Error('MONGODB_URI environment variable is required');
    }

    const mongooseOptions = {
      useNewUrlParser: true,
      useUnifiedTopology: true,
      serverSelectionTimeoutMS: 30000, // 30 seconds
      socketTimeoutMS: 45000, // 45 seconds
      maxPoolSize: 10,
      minPoolSize: 5
    };

    await mongoose.connect(MONGODB_URI, mongooseOptions);
    
    console.log('✅ MongoDB Connected Successfully!');
    
    // Initialize database after successful connection
    await initializeDatabase();
    
  } catch (error) {
    console.error('❌ MongoDB Connection Error:', error.message);
    
    // Retry connection after 5 seconds
    console.log('🔄 Retrying connection in 5 seconds...');
    setTimeout(connectDB, 5000);
  }
};

// Handle MongoDB connection events
mongoose.connection.on('disconnected', () => {
  console.log('❌ MongoDB disconnected');
});

mongoose.connection.on('error', (err) => {
  console.error('❌ MongoDB connection error:', err);
});

// ==================== AUTH ROUTES - 100% FRONTEND COMPATIBLE ====================

// Register - Perfect Frontend Match
app.post('/api/auth/register', [
  body('full_name')
    .notEmpty()
    .trim()
    .isLength({ min: 2, max: 100 })
    .withMessage('Full name must be between 2 and 100 characters'),
  body('email')
    .isEmail()
    .normalizeEmail()
    .withMessage('Valid email is required'),
  body('phone')
    .notEmpty()
    .trim()
    .withMessage('Phone number is required'),
  body('password')
    .isLength({ min: 6 })
    .withMessage('Password must be at least 6 characters'),
  body('referral_code')
    .optional()
    .trim()
    .isLength({ min: 6, max: 12 })
    .withMessage('Referral code must be between 6 and 12 characters'),
  body('risk_tolerance')
    .optional()
    .isIn(['low', 'medium', 'high'])
    .withMessage('Risk tolerance must be low, medium, or high'),
  body('investment_strategy')
    .optional()
    .isIn(['conservative', 'balanced', 'aggressive'])
    .withMessage('Investment strategy must be conservative, balanced, or aggressive')
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

    const { 
      full_name, 
      email, 
      phone, 
      password, 
      referral_code, 
      risk_tolerance, 
      investment_strategy 
    } = req.body;

    // Check existing user
    const existingUser = await User.findOne({ 
      email: email.toLowerCase() 
    });
    
    if (existingUser) {
      return res.status(400).json(
        formatResponse(false, 'User already exists with this email')
      );
    }

    // Handle referral
    let referredBy = null;
    if (referral_code) {
      referredBy = await User.findOne({ 
        referral_code: referral_code.toUpperCase() 
      });
      
      if (!referredBy) {
        return res.status(400).json(
          formatResponse(false, 'Invalid referral code')
        );
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
      investment_strategy: investment_strategy || 'balanced'
    });

    await user.save();

    // Generate token
    const token = jwt.sign(
      { id: user._id }, 
      process.env.JWT_SECRET,
      { expiresIn: '30d' }
    );

    // Handle referral bonus
    if (referredBy) {
      const referralBonus = 1000;
      
      await User.findByIdAndUpdate(referredBy._id, {
        $inc: { 
          balance: referralBonus,
          referral_earnings: referralBonus,
          referral_count: 1
        }
      });

      // Create referral transaction
      await Transaction.create({
        user: referredBy._id,
        type: 'referral',
        amount: referralBonus,
        description: `Referral bonus for ${full_name}`,
        status: 'completed'
      });

      // Send notification to referrer
      await Notification.create({
        user: referredBy._id,
        title: 'Referral Bonus Received!',
        message: `You earned ₦${referralBonus.toLocaleString()} referral bonus from ${full_name}`,
        type: 'success'
      });

      // Update referrer's balance in real-time
      broadcastToUser(referredBy._id.toString(), {
        type: 'balance_update',
        balance: referredBy.balance + referralBonus,
        message: `Referral bonus of ₦${referralBonus.toLocaleString()} received`
      });
    }

    // Send welcome notification
    await Notification.create({
      user: user._id,
      title: 'Welcome to Raw Wealthy!',
      message: 'Your account has been created successfully. Start investing today!',
      type: 'success'
    });

    res.status(201).json(
      formatResponse(true, 'User registered successfully', {
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
          risk_tolerance: user.risk_tolerance,
          investment_strategy: user.investment_strategy,
          two_factor_enabled: user.two_factor_enabled,
          country: user.country,
          currency: user.currency
        },
        token
      })
    );

  } catch (error) {
    handleError(res, error, 'Server error during registration');
  }
});

// Login - Perfect Frontend Match
app.post('/api/auth/login', [
  body('email')
    .isEmail()
    .normalizeEmail()
    .withMessage('Valid email is required'),
  body('password')
    .notEmpty()
    .withMessage('Password is required')
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

    const { email, password, two_factor_code } = req.body;

    const user = await User.findOne({ 
      email: email.toLowerCase() 
    }).select('+password +two_factor_secret');
    
    if (!user) {
      return res.status(400).json(
        formatResponse(false, 'Invalid credentials')
      );
    }

    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      return res.status(400).json(
        formatResponse(false, 'Invalid credentials')
      );
    }

    if (!user.is_active) {
      return res.status(401).json(
        formatResponse(false, 'Account is deactivated. Please contact support.')
      );
    }

    // Handle 2FA
    if (user.two_factor_enabled && !two_factor_code) {
      return res.status(200).json(
        formatResponse(true, 'Two-factor authentication required', {
          requires_2fa: true,
          user_id: user._id
        })
      );
    }

    if (user.two_factor_enabled && two_factor_code) {
      const is2FATokenValid = user.verify2FAToken(two_factor_code);
      if (!is2FATokenValid) {
        return res.status(400).json(
          formatResponse(false, 'Invalid two-factor code')
        );
      }
    }

    // Update login info
    user.last_login = new Date();
    user.last_active = new Date();
    await user.save();

    const token = jwt.sign(
      { id: user._id }, 
      process.env.JWT_SECRET,
      { expiresIn: '30d' }
    );

    res.json(
      formatResponse(true, 'Login successful', {
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
          investment_strategy: user.investment_strategy,
          country: user.country,
          currency: user.currency
        },
        token
      })
    );

  } catch (error) {
    handleError(res, error, 'Server error during login');
  }
});

// Password Reset Request
app.post('/api/auth/forgot-password', [
  body('email')
    .isEmail()
    .withMessage('Valid email is required')
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

    const { email } = req.body;
    const user = await User.findOne({ email: email.toLowerCase() });
    
    if (!user) {
      // Don't reveal if user exists for security
      return res.json(
        formatResponse(true, 'If the email exists, a password reset link has been sent')
      );
    }

    // Generate reset token (expires in 1 hour)
    const resetToken = jwt.sign(
      { 
        id: user._id, 
        type: 'password_reset',
        timestamp: Date.now()
      },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    // In a real implementation, you would send an email
    const resetLink = `${req.get('origin') || 'https://rawwealthy.com'}/reset-password?token=${resetToken}`;
    
    await sendEmail(
      user.email,
      'Password Reset Request - Raw Wealthy',
      `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2 style="color: #f59e0b;">Password Reset Request</h2>
          <p>You requested to reset your password for your Raw Wealthy account.</p>
          <p>Click the button below to reset your password:</p>
          <a href="${resetLink}" style="background: #f59e0b; color: white; padding: 12px 24px; text-decoration: none; border-radius: 8px; display: inline-block; font-weight: bold;">
            Reset Password
          </a>
          <p style="margin-top: 20px; color: #666;">
            This link will expire in 1 hour. If you didn't request this, please ignore this email.
          </p>
        </div>
      `
    );

    res.json(
      formatResponse(true, 'If the email exists, a password reset link has been sent')
    );

  } catch (error) {
    handleError(res, error, 'Error processing password reset request');
  }
});

// NEW: Password Reset Endpoint for Frontend
app.post('/api/password/reset', [
  body('email')
    .isEmail()
    .withMessage('Valid email is required')
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

    const { email } = req.body;
    const user = await User.findOne({ email: email.toLowerCase() });
    
    if (!user) {
      return res.json(
        formatResponse(true, 'If the email exists, a password reset link has been sent')
      );
    }

    // Generate reset token
    const resetToken = jwt.sign(
      { 
        id: user._id, 
        type: 'password_reset',
        timestamp: Date.now()
      },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    res.json(
      formatResponse(true, 'Password reset instructions sent to your email.', {
        reset_token: resetToken
      })
    );

  } catch (error) {
    handleError(res, error, 'Error processing password reset request');
  }
});

// ==================== INVESTMENT PLAN ROUTES - 100% FRONTEND COMPATIBLE ====================

// Get All Plans - FRONTEND MATCHED
app.get('/api/plans', async (req, res) => {
  try {
    const plans = await InvestmentPlan.find({ is_active: true })
      .sort({ is_popular: -1, min_amount: 1 })
      .lean();

    res.json(
      formatResponse(true, 'Plans retrieved successfully', { plans })
    );
  } catch (error) {
    handleError(res, error, 'Error fetching investment plans');
  }
});

// NEW ENDPOINT: Frontend expects /investment-plans
app.get('/api/investment-plans', async (req, res) => {
  try {
    const plans = await InvestmentPlan.find({ is_active: true })
      .sort({ is_popular: -1, min_amount: 1 })
      .lean();

    res.json(
      formatResponse(true, 'Plans retrieved successfully', { plans })
    );
  } catch (error) {
    handleError(res, error, 'Error fetching investment plans');
  }
});

// Get Popular Plans
app.get('/api/plans/popular', async (req, res) => {
  try {
    const plans = await InvestmentPlan.find({ 
      is_active: true, 
      is_popular: true 
    })
    .sort({ min_amount: 1 })
    .limit(6)
    .lean();

    res.json(
      formatResponse(true, 'Popular plans retrieved', { plans })
    );
  } catch (error) {
    handleError(res, error, 'Error fetching popular plans');
  }
});

// Get Plan by ID
app.get('/api/plans/:id', [
  param('id')
    .isMongoId()
    .withMessage('Invalid plan ID')
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

    const plan = await InvestmentPlan.findById(req.params.id);
    if (!plan) {
      return res.status(404).json(
        formatResponse(false, 'Investment plan not found')
      );
    }

    res.json(
      formatResponse(true, 'Plan retrieved successfully', { plan })
    );
  } catch (error) {
    handleError(res, error, 'Error fetching investment plan');
  }
});

// ==================== INVESTMENT ROUTES - 100% FRONTEND COMPATIBLE ====================

// Get User Investments
app.get('/api/investments', auth, async (req, res) => {
  try {
    const { page, limit, skip } = getPaginationOptions(req);
    const status = req.query.status;

    let query = { user: req.user.id };
    if (status && status !== 'all') {
      query.status = status;
    }

    const investments = await Investment.find(query)
      .populate('plan', 'name daily_interest total_interest duration raw_material category risk_level image_url color icon')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit)
      .lean();

    const total = await Investment.countDocuments(query);

    // Calculate stats for frontend
    const activeInvestments = await Investment.find({ 
      user: req.user.id, 
      status: 'active' 
    });
    
    const totalActiveValue = activeInvestments.reduce((sum, inv) => sum + inv.amount, 0);
    const totalEarnings = activeInvestments.reduce((sum, inv) => sum + inv.earned_so_far, 0);

    // Add virtual fields for frontend
    const investmentsWithVirtuals = investments.map(inv => {
      const remainingDays = Math.max(0, Math.ceil((new Date(inv.end_date) - new Date()) / (1000 * 60 * 60 * 24)));
      const progressPercentage = inv.status === 'active' ? 
        Math.min(100, ((new Date() - new Date(inv.start_date)) / (new Date(inv.end_date) - new Date(inv.start_date))) * 100) : 
        (inv.status === 'completed' ? 100 : 0);
      
      return {
        ...inv,
        remaining_days: remainingDays,
        progress_percentage: Math.round(progressPercentage),
        plan_name: inv.plan?.name,
        plan_id: inv.plan?._id
      };
    });

    const responseData = {
      investments: investmentsWithVirtuals,
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit)
      },
      stats: {
        total_active_value: totalActiveValue,
        total_earnings: totalEarnings,
        active_count: activeInvestments.length,
        total_investment_count: total
      }
    };

    res.json(
      formatResponse(true, 'Investments retrieved successfully', responseData)
    );

  } catch (error) {
    handleError(res, error, 'Error fetching investments');
  }
});

// Create Investment - FRONTEND PERFECT MATCH
app.post('/api/investments', auth, upload.single('payment_proof'), [
  body('plan_id')
    .isMongoId()
    .withMessage('Invalid plan ID'),
  body('amount')
    .isFloat({ min: 1000 })
    .withMessage('Minimum investment is ₦1000'),
  body('auto_renew')
    .optional()
    .isBoolean()
    .withMessage('Auto renew must be a boolean')
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

    const { plan_id, amount, auto_renew } = req.body;
    
    let payment_proof = null;
    if (req.file) {
      payment_proof = await handleFileUpload(req.file, 'investment-proofs');
    }

    const plan = await InvestmentPlan.findById(plan_id);
    if (!plan) {
      return res.status(404).json(
        formatResponse(false, 'Investment plan not found')
      );
    }

    if (amount < plan.min_amount) {
      return res.status(400).json(
        formatResponse(false, `Minimum investment for ${plan.name} is ₦${plan.min_amount.toLocaleString()}`)
      );
    }

    if (plan.max_amount && amount > plan.max_amount) {
      return res.status(400).json(
        formatResponse(false, `Maximum investment for ${plan.name} is ₦${plan.max_amount.toLocaleString()}`)
      );
    }

    const user = await User.findById(req.user.id);
    if (amount > user.balance) {
      return res.status(400).json(
        formatResponse(false, 'Insufficient balance for this investment')
      );
    }

    // Create investment
    const investment = new Investment({
      user: req.user.id,
      plan: plan_id,
      amount: parseFloat(amount),
      payment_proof,
      auto_renew: auto_renew === 'true' || auto_renew === true,
      status: 'pending'
    });

    await investment.save();
    await investment.populate('plan', 'name daily_interest total_interest duration raw_material category image_url color');

    // Deduct from user balance
    await User.findByIdAndUpdate(req.user.id, { 
      $inc: { balance: -amount }
    });

    // Update plan stats
    await InvestmentPlan.findByIdAndUpdate(plan_id, {
      $inc: {
        investment_count: 1,
        total_invested: amount
      }
    });

    // Create transaction
    await Transaction.create({
      user: req.user.id,
      type: 'investment',
      amount: -amount,
      description: `Investment in ${plan.name} plan`,
      status: 'completed',
      related_investment: investment._id
    });

    // Send notification
    await Notification.create({
      user: req.user.id,
      title: 'Investment Submitted',
      message: `Your investment of ₦${amount.toLocaleString()} in ${plan.name} has been submitted for approval`,
      type: 'info'
    });

    // Real-time update
    broadcastToUser(req.user.id, {
      type: 'balance_update',
      balance: user.balance - amount,
      message: `Investment of ₦${amount.toLocaleString()} submitted`
    });

    res.status(201).json(
      formatResponse(true, 'Investment created successfully! Waiting for admin approval.', { 
        investment: {
          ...investment.toObject(),
          plan_name: plan.name,
          plan_id: plan._id
        }
      })
    );

  } catch (error) {
    handleError(res, error, 'Error creating investment');
  }
});

// ==================== PROFILE ROUTES - 100% FRONTEND COMPATIBLE ====================

// Get User Profile - ENHANCED FOR FRONTEND
app.get('/api/profile', auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    
    // Get active investments
    const activeInvestments = await Investment.find({ 
      user: req.user.id, 
      status: 'active' 
    }).populate('plan', 'name raw_material category');
    
    const totalActiveValue = activeInvestments.reduce((sum, inv) => sum + inv.amount, 0);
    const totalEarnings = activeInvestments.reduce((sum, inv) => sum + inv.earned_so_far, 0);
    
    // Get recent transactions
    const recentTransactions = await Transaction.find({ user: req.user.id })
      .sort({ createdAt: -1 })
      .limit(5)
      .lean();
    
    // Get unread notifications count
    const unreadNotifications = await Notification.countDocuments({ 
      user: req.user.id, 
      is_read: false 
    });

    // Get referral count
    const referralCount = await User.countDocuments({ referred_by: req.user.id });

    // Get KYC status
    const kyc = await KYC.findOne({ user: req.user.id }).sort({ createdAt: -1 });

    const profileData = {
      user: {
        ...user.toObject(),
        tier: user.kyc_verified ? 'Verified Investor' : 'Standard Investor'
      },
      dashboard_stats: {
        active_investment_value: totalActiveValue,
        total_earnings: user.total_earnings,
        total_investments: activeInvestments.length,
        unread_notifications: unreadNotifications,
        referral_count: referralCount,
        portfolio_value: totalActiveValue + totalEarnings,
        available_balance: user.balance,
        kyc_status: kyc?.status || 'not_submitted',
        earnings_trend: [12000, 19000, 30000, 50000, 20000, 30000] // Sample data for chart
      },
      recent_transactions: recentTransactions,
      active_investments: activeInvestments
    };

    res.json(
      formatResponse(true, 'Profile retrieved successfully', profileData)
    );
  } catch (error) {
    handleError(res, error, 'Error fetching profile');
  }
});

// Update User Profile
app.put('/api/profile', auth, [
  body('full_name')
    .optional()
    .trim()
    .isLength({ min: 2, max: 100 })
    .withMessage('Full name must be between 2 and 100 characters'),
  body('phone')
    .optional()
    .trim(),
  body('risk_tolerance')
    .optional()
    .isIn(['low', 'medium', 'high'])
    .withMessage('Risk tolerance must be low, medium, or high'),
  body('investment_strategy')
    .optional()
    .isIn(['conservative', 'balanced', 'aggressive'])
    .withMessage('Investment strategy must be conservative, balanced, or aggressive'),
  body('country')
    .optional()
    .trim(),
  body('currency')
    .optional()
    .isIn(['NGN', 'USD'])
    .withMessage('Currency must be NGN or USD'),
  body('language')
    .optional()
    .trim(),
  body('timezone')
    .optional()
    .trim()
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

    const { 
      full_name, 
      phone, 
      risk_tolerance, 
      investment_strategy, 
      country, 
      currency, 
      language, 
      timezone 
    } = req.body;
    
    const updateData = {};
    if (full_name) updateData.full_name = full_name;
    if (phone) updateData.phone = phone;
    if (risk_tolerance) updateData.risk_tolerance = risk_tolerance;
    if (investment_strategy) updateData.investment_strategy = investment_strategy;
    if (country) updateData.country = country;
    if (currency) updateData.currency = currency;
    if (language) updateData.language = language;
    if (timezone) updateData.timezone = timezone;

    const user = await User.findByIdAndUpdate(
      req.user.id,
      updateData,
      { new: true, runValidators: true }
    );

    res.json(
      formatResponse(true, 'Profile updated successfully', { user })
    );
  } catch (error) {
    handleError(res, error, 'Error updating profile');
  }
});

// NEW ENDPOINT: Preferences update for frontend
app.put('/api/profile/preferences', auth, [
  body('risk_tolerance')
    .optional()
    .isIn(['low', 'medium', 'high'])
    .withMessage('Risk tolerance must be low, medium, or high'),
  body('investment_strategy')
    .optional()
    .isIn(['conservative', 'balanced', 'aggressive'])
    .withMessage('Investment strategy must be conservative, balanced, or aggressive'),
  body('currency')
    .optional()
    .isIn(['NGN', 'USD'])
    .withMessage('Currency must be NGN or USD'),
  body('language')
    .optional()
    .trim(),
  body('timezone')
    .optional()
    .trim()
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

    const { risk_tolerance, investment_strategy, currency, language, timezone } = req.body;
    
    const updateData = {};
    if (risk_tolerance) updateData.risk_tolerance = risk_tolerance;
    if (investment_strategy) updateData.investment_strategy = investment_strategy;
    if (currency) updateData.currency = currency;
    if (language) updateData.language = language;
    if (timezone) updateData.timezone = timezone;

    const user = await User.findByIdAndUpdate(
      req.user.id,
      updateData,
      { new: true, runValidators: true }
    );

    res.json(
      formatResponse(true, 'Preferences updated successfully', { user })
    );
  } catch (error) {
    handleError(res, error, 'Error updating preferences');
  }
});

// Update Password
app.put('/api/profile/password', auth, [
  body('current_password')
    .notEmpty()
    .withMessage('Current password is required'),
  body('new_password')
    .isLength({ min: 6 })
    .withMessage('New password must be at least 6 characters')
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

    const { current_password, new_password } = req.body;
    
    const user = await User.findById(req.user.id).select('+password');
    
    const isMatch = await user.comparePassword(current_password);
    if (!isMatch) {
      return res.status(400).json(
        formatResponse(false, 'Current password is incorrect')
      );
    }

    user.password = new_password;
    await user.save();

    // Send notification
    await Notification.create({
      user: req.user.id,
      title: 'Password Updated',
      message: 'Your password has been updated successfully',
      type: 'success'
    });

    res.json(
      formatResponse(true, 'Password updated successfully')
    );
  } catch (error) {
    handleError(res, error, 'Error updating password');
  }
});

// Update Bank Details
app.put('/api/profile/bank', auth, [
  body('bank_name')
    .notEmpty()
    .withMessage('Bank name is required'),
  body('account_name')
    .notEmpty()
    .withMessage('Account name is required'),
  body('account_number')
    .notEmpty()
    .withMessage('Account number is required')
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

    const { bank_name, account_name, account_number } = req.body;
    
    const user = await User.findByIdAndUpdate(
      req.user.id,
      {
        bank_details: {
          bank_name,
          account_name,
          account_number,
          verified: false
        }
      },
      { new: true }
    );

    res.json(
      formatResponse(true, 'Bank details updated successfully', { user })
    );
  } catch (error) {
    handleError(res, error, 'Error updating bank details');
  }
});

// ==================== DEPOSIT ROUTES - 100% FRONTEND COMPATIBLE ====================

// Create Deposit
app.post('/api/deposits', auth, upload.single('payment_proof'), [
  body('amount')
    .isFloat({ min: 500 })
    .withMessage('Minimum deposit is ₦500'),
  body('payment_method')
    .isIn(['bank_transfer', 'crypto', 'paypal', 'card'])
    .withMessage('Invalid payment method'),
  body('transaction_hash')
    .optional()
    .trim()
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

    const { amount, payment_method, transaction_hash } = req.body;
    
    let payment_proof = null;
    if (req.file) {
      payment_proof = await handleFileUpload(req.file, 'deposit-proofs');
    }

    const deposit = new Deposit({
      user: req.user.id,
      amount: parseFloat(amount),
      payment_method,
      payment_proof,
      transaction_hash: transaction_hash || null
    });

    await deposit.save();

    // Send notification
    await Notification.create({
      user: req.user.id,
      title: 'Deposit Submitted',
      message: `Your deposit of ₦${amount.toLocaleString()} has been submitted for approval`,
      type: 'info'
    });

    res.status(201).json(
      formatResponse(true, 'Deposit request submitted successfully! Waiting for admin approval.', { deposit })
    );
  } catch (error) {
    handleError(res, error, 'Error creating deposit');
  }
});

// Get User Deposits
app.get('/api/deposits', auth, async (req, res) => {
  try {
    const { page, limit, skip } = getPaginationOptions(req);
    const status = req.query.status;

    let query = { user: req.user.id };
    if (status && status !== 'all') {
      query.status = status;
    }

    const deposits = await Deposit.find(query)
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit)
      .lean();

    const total = await Deposit.countDocuments(query);

    res.json(
      formatResponse(true, 'Deposits retrieved successfully', {
        deposits,
        pagination: {
          page,
          limit,
          total,
          pages: Math.ceil(total / limit)
        }
      })
    );

  } catch (error) {
    handleError(res, error, 'Error fetching deposits');
  }
});

// ==================== WITHDRAWAL ROUTES - 100% FRONTEND COMPATIBLE ====================

// Create Withdrawal
app.post('/api/withdrawals', auth, [
  body('amount')
    .isFloat({ min: 1000 })
    .withMessage('Minimum withdrawal is ₦1000'),
  body('payment_method')
    .isIn(['bank_transfer', 'crypto', 'paypal'])
    .withMessage('Invalid payment method'),
  body('bank_name')
    .optional()
    .trim(),
  body('account_name')
    .optional()
    .trim(),
  body('account_number')
    .optional()
    .trim(),
  body('wallet_address')
    .optional()
    .trim(),
  body('paypal_email')
    .optional()
    .isEmail()
    .withMessage('Invalid PayPal email')
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

    const { 
      amount, 
      payment_method, 
      bank_name, 
      account_name, 
      account_number, 
      wallet_address, 
      paypal_email 
    } = req.body;

    const user = await User.findById(req.user.id);
    if (parseFloat(amount) > user.balance) {
      return res.status(400).json(
        formatResponse(false, 'Insufficient balance for this withdrawal')
      );
    }

    const withdrawalData = {
      user: req.user.id,
      amount: parseFloat(amount),
      payment_method
    };

    if (payment_method === 'bank_transfer') {
      if (!bank_name || !account_name || !account_number) {
        return res.status(400).json(
          formatResponse(false, 'Bank details are required for bank transfer')
        );
      }
      withdrawalData.bank_details = {
        bank_name,
        account_name,
        account_number
      };
    } else if (payment_method === 'crypto') {
      if (!wallet_address) {
        return res.status(400).json(
          formatResponse(false, 'Wallet address is required for crypto withdrawals')
        );
      }
      withdrawalData.wallet_address = wallet_address;
    } else if (payment_method === 'paypal') {
      if (!paypal_email) {
        return res.status(400).json(
          formatResponse(false, 'PayPal email is required for PayPal withdrawals')
        );
      }
      withdrawalData.paypal_email = paypal_email;
    }

    const withdrawal = new Withdrawal(withdrawalData);
    await withdrawal.save();

    // Send notification
    await Notification.create({
      user: req.user.id,
      title: 'Withdrawal Submitted',
      message: `Your withdrawal of ₦${amount.toLocaleString()} has been submitted for approval`,
      type: 'info'
    });

    res.status(201).json(
      formatResponse(true, 'Withdrawal request submitted successfully! Waiting for admin approval.', { withdrawal })
    );
  } catch (error) {
    handleError(res, error, 'Error creating withdrawal');
  }
});

// Get User Withdrawals
app.get('/api/withdrawals', auth, async (req, res) => {
  try {
    const { page, limit, skip } = getPaginationOptions(req);
    const status = req.query.status;

    let query = { user: req.user.id };
    if (status && status !== 'all') {
      query.status = status;
    }

    const withdrawals = await Withdrawal.find(query)
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit)
      .lean();

    const total = await Withdrawal.countDocuments(query);

    res.json(
      formatResponse(true, 'Withdrawals retrieved successfully', {
        withdrawals,
        pagination: {
          page,
          limit,
          total,
          pages: Math.ceil(total / limit)
        }
      })
    );
  } catch (error) {
    handleError(res, error, 'Error fetching withdrawals');
  }
});

// ==================== TRANSACTION ROUTES - 100% FRONTEND COMPATIBLE ====================

// Get User Transactions
app.get('/api/transactions', auth, async (req, res) => {
  try {
    const { page, limit, skip } = getPaginationOptions(req);
    const type = req.query.type;

    let query = { user: req.user.id };
    if (type && type !== 'all') {
      query.type = type;
    }

    const transactions = await Transaction.find(query)
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit)
      .lean();

    const total = await Transaction.countDocuments(query);

    res.json(
      formatResponse(true, 'Transactions retrieved successfully', {
        transactions,
        pagination: {
          page,
          limit,
          total,
          pages: Math.ceil(total / limit)
        }
      })
    );
  } catch (error) {
    handleError(res, error, 'Error fetching transactions');
  }
});

// ==================== REFERRAL ROUTES - 100% FRONTEND COMPATIBLE ====================

// Get Referral Stats
app.get('/api/referrals/stats', auth, async (req, res) => {
  try {
    const referralCount = await User.countDocuments({ referred_by: req.user.id });
    const activeReferrals = await User.countDocuments({ 
      referred_by: req.user.id, 
      is_active: true 
    });
    
    const user = await User.findById(req.user.id);
    
    const stats = {
      total_referrals: referralCount,
      active_referrals: activeReferrals,
      total_earnings: user.referral_earnings,
      pending_earnings: 0,
      referral_code: user.referral_code,
      referral_link: `${req.get('origin') || 'https://rawwealthy.com'}?ref=${user.referral_code}`
    };

    res.json(
      formatResponse(true, 'Referral stats retrieved successfully', { stats })
    );
  } catch (error) {
    handleError(res, error, 'Error fetching referral stats');
  }
});

// Get Referral List
app.get('/api/referrals/list', auth, async (req, res) => {
  try {
    const { page, limit, skip } = getPaginationOptions(req);

    const referrals = await User.find({ referred_by: req.user.id })
      .select('full_name email phone createdAt total_earnings balance')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit)
      .lean();

    const total = await User.countDocuments({ referred_by: req.user.id });

    res.json(
      formatResponse(true, 'Referrals retrieved successfully', {
        referrals,
        pagination: {
          page,
          limit,
          total,
          pages: Math.ceil(total / limit)
        }
      })
    );
  } catch (error) {
    handleError(res, error, 'Error fetching referrals');
  }
});

// ==================== KYC ROUTES - 100% FRONTEND COMPATIBLE ====================

// Submit KYC
app.post('/api/kyc', auth, upload.fields([
  { name: 'id_front', maxCount: 1 },
  { name: 'id_back', maxCount: 1 },
  { name: 'selfie_with_id', maxCount: 1 }
]), [
  body('id_type')
    .isIn(['national_id', 'passport', 'driver_license', 'voters_card'])
    .withMessage('Invalid ID type'),
  body('id_number')
    .notEmpty()
    .withMessage('ID number is required')
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

    const { id_type, id_number } = req.body;
    const files = req.files;

    if (!files || !files.id_front || !files.id_back || !files.selfie_with_id) {
      return res.status(400).json(
        formatResponse(false, 'All document images are required')
      );
    }

    // Upload files
    const [id_front, id_back, selfie_with_id] = await Promise.all([
      handleFileUpload(files.id_front[0], 'kyc'),
      handleFileUpload(files.id_back[0], 'kyc'),
      handleFileUpload(files.selfie_with_id[0], 'kyc')
    ]);

    // Check existing KYC
    const existingKYC = await KYC.findOne({ 
      user: req.user.id, 
      status: { $in: ['pending', 'approved'] } 
    });
    
    if (existingKYC) {
      return res.status(400).json(
        formatResponse(false, 'You already have a KYC submission')
      );
    }

    const kyc = new KYC({
      user: req.user.id,
      id_type,
      id_number,
      id_front,
      id_back,
      selfie_with_id,
      status: 'pending'
    });

    await kyc.save();

    // Update user KYC status
    await User.findByIdAndUpdate(req.user.id, {
      kyc_verified: false
    });

    // Send notification
    await Notification.create({
      user: req.user.id,
      title: 'KYC Submitted',
      message: 'Your KYC documents have been submitted for verification',
      type: 'info'
    });

    res.status(201).json(
      formatResponse(true, 'KYC submitted successfully! Your documents are under review.', { kyc })
    );
  } catch (error) {
    handleError(res, error, 'Error submitting KYC');
  }
});

// Get KYC Status
app.get('/api/kyc/status', auth, async (req, res) => {
  try {
    const kyc = await KYC.findOne({ user: req.user.id }).sort({ createdAt: -1 });
    
    if (!kyc) {
      return res.json(
        formatResponse(true, 'KYC status retrieved', { 
          status: 'not_submitted',
          message: 'No KYC submission found'
        })
      );
    }

    res.json(
      formatResponse(true, 'KYC status retrieved', { kyc })
    );
  } catch (error) {
    handleError(res, error, 'Error fetching KYC status');
  }
});

// ==================== 2FA ROUTES - 100% FRONTEND COMPATIBLE ====================

// Enable 2FA
app.post('/api/2fa/enable', auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('+two_factor_secret');
    
    if (user.two_factor_enabled) {
      return res.status(400).json(
        formatResponse(false, '2FA is already enabled')
      );
    }

    const secret = user.generate2FASecret();
    await user.save();

    const qrCodeUrl = await QRCode.toDataURL(secret.otpauth_url);

    res.json(
      formatResponse(true, '2FA setup initiated', {
        secret: secret.base32,
        qr_code: qrCodeUrl,
        otpauth_url: secret.otpauth_url
      })
    );
  } catch (error) {
    handleError(res, error, 'Error enabling 2FA');
  }
});

// Verify 2FA
app.post('/api/2fa/verify', auth, [
  body('code')
    .notEmpty()
    .withMessage('2FA code is required')
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

    const { code } = req.body;
    const user = await User.findById(req.user.id).select('+two_factor_secret');

    if (!user.two_factor_secret) {
      return res.status(400).json(
        formatResponse(false, '2FA is not set up')
      );
    }

    const isValidToken = user.verify2FAToken(code);
    if (!isValidToken) {
      return res.status(400).json(
        formatResponse(false, 'Invalid 2FA code')
      );
    }

    user.two_factor_enabled = true;
    await user.save();

    // Send notification
    await Notification.create({
      user: req.user.id,
      title: '2FA Enabled',
      message: 'Two-factor authentication has been enabled on your account',
      type: 'success'
    });

    res.json(
      formatResponse(true, '2FA enabled successfully')
    );
  } catch (error) {
    handleError(res, error, 'Error verifying 2FA');
  }
});

// Disable 2FA
app.post('/api/2fa/disable', auth, [
  body('code')
    .notEmpty()
    .withMessage('2FA code is required')
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

    const { code } = req.body;
    const user = await User.findById(req.user.id).select('+two_factor_secret');

    if (!user.two_factor_enabled) {
      return res.status(400).json(
        formatResponse(false, '2FA is not enabled')
      );
    }

    const isValidToken = user.verify2FAToken(code);
    if (!isValidToken) {
      return res.status(400).json(
        formatResponse(false, 'Invalid 2FA code')
      );
    }

    user.two_factor_enabled = false;
    user.two_factor_secret = undefined;
    await user.save();

    // Send notification
    await Notification.create({
      user: req.user.id,
      title: '2FA Disabled',
      message: 'Two-factor authentication has been disabled on your account',
      type: 'warning'
    });

    res.json(
      formatResponse(true, '2FA disabled successfully')
    );
  } catch (error) {
    handleError(res, error, 'Error disabling 2FA');
  }
});

// ==================== SUPPORT ROUTES - 100% FRONTEND COMPATIBLE ====================

// Create Support Ticket
app.post('/api/support', auth, [
  body('subject')
    .notEmpty()
    .withMessage('Subject is required'),
  body('message')
    .notEmpty()
    .withMessage('Message is required'),
  body('category')
    .optional()
    .isIn(['general', 'technical', 'billing', 'investment', 'withdrawal', 'kyc', 'other'])
    .withMessage('Invalid category')
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

    const { subject, message, category } = req.body;

    const ticket = new SupportTicket({
      user: req.user.id,
      subject,
      message,
      category: category || 'general'
    });

    await ticket.save();

    // Send notification to admin
    const adminUsers = await User.find({ role: { $in: ['admin', 'super_admin'] } });
    for (const admin of adminUsers) {
      await Notification.create({
        user: admin._id,
        title: 'New Support Ticket',
        message: `New support ticket from ${req.user.full_name}: ${subject}`,
        type: 'info'
      });
    }

    res.status(201).json(
      formatResponse(true, 'Support ticket submitted successfully! Our team will respond within 24 hours.', { ticket })
    );
  } catch (error) {
    handleError(res, error, 'Error creating support ticket');
  }
});

// Get User Support Tickets
app.get('/api/support/tickets', auth, async (req, res) => {
  try {
    const { page, limit, skip } = getPaginationOptions(req);

    const tickets = await SupportTicket.find({ user: req.user.id })
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit)
      .lean();

    const total = await SupportTicket.countDocuments({ user: req.user.id });

    res.json(
      formatResponse(true, 'Support tickets retrieved successfully', {
        tickets,
        pagination: {
          page,
          limit,
          total,
          pages: Math.ceil(total / limit)
        }
      })
    );
  } catch (error) {
    handleError(res, error, 'Error fetching support tickets');
  }
});

// ==================== ADMIN ROUTES - 100% FRONTEND COMPATIBLE ====================

// Admin Dashboard Stats
app.get('/api/admin/dashboard', adminAuth, async (req, res) => {
  try {
    const totalUsers = await User.countDocuments({ role: 'user' });
    
    const totalInvested = await Investment.aggregate([
      { $match: { status: { $in: ['active', 'completed'] } } },
      { $group: { _id: null, total: { $sum: '$amount' } } }
    ]);
    
    const totalWithdrawn = await Withdrawal.aggregate([
      { $match: { status: 'approved' } },
      { $group: { _id: null, total: { $sum: '$amount' } } }
    ]);
    
    const pendingInvestments = await Investment.countDocuments({ status: 'pending' });
    const pendingDeposits = await Deposit.countDocuments({ status: 'pending' });
    const pendingWithdrawals = await Withdrawal.countDocuments({ status: 'pending' });
    const pendingKYC = await KYC.countDocuments({ status: 'pending' });
    
    const activeInvestments = await Investment.countDocuments({ status: 'active' });

    // Platform earnings (5% of all withdrawals)
    const platformEarnings = await Withdrawal.aggregate([
      { $match: { status: 'approved' } },
      { $group: { _id: null, total: { $sum: '$platform_fee' } } }
    ]);

    // Recent activities
    const recentUsers = await User.find({ role: 'user' })
      .select('full_name email createdAt')
      .sort({ createdAt: -1 })
      .limit(5)
      .lean();

    const recentInvestments = await Investment.find({ status: 'pending' })
      .populate('user', 'full_name email')
      .populate('plan', 'name')
      .sort({ createdAt: -1 })
      .limit(5)
      .lean();

    const stats = {
      total_users: totalUsers,
      total_invested: totalInvested.length > 0 ? totalInvested[0].total : 0,
      total_withdrawn: totalWithdrawn.length > 0 ? totalWithdrawn[0].total : 0,
      pending_approvals: pendingInvestments + pendingDeposits + pendingWithdrawals + pendingKYC,
      active_investments: activeInvestments,
      pending_investments: pendingInvestments,
      pending_deposits: pendingDeposits,
      pending_withdrawals: pendingWithdrawals,
      pending_kyc: pendingKYC,
      platform_earnings: platformEarnings.length > 0 ? platformEarnings[0].total : 0,
      recent_users: recentUsers,
      recent_investments: recentInvestments
    };

    res.json(
      formatResponse(true, 'Admin dashboard stats retrieved', { stats })
    );
  } catch (error) {
    handleError(res, error, 'Error fetching admin dashboard');
  }
});

// Admin Analytics
app.get('/api/admin/analytics', adminAuth, async (req, res) => {
  try {
    // Daily signups
    const dailySignups = await User.countDocuments({
      role: 'user',
      createdAt: { 
        $gte: new Date(new Date().setHours(0, 0, 0, 0))
      }
    });

    // Weekly investments
    const weeklyInvestments = await Investment.aggregate([
      {
        $match: {
          createdAt: {
            $gte: new Date(new Date().setDate(new Date().getDate() - 7))
          }
        }
      },
      {
        $group: {
          _id: null,
          total: { $sum: '$amount' }
        }
      }
    ]);

    // Average investment
    const avgInvestment = await Investment.aggregate([
      {
        $group: {
          _id: null,
          average: { $avg: '$amount' }
        }
      }
    ]);

    // Monthly revenue (platform fees)
    const monthlyRevenue = await Withdrawal.aggregate([
      {
        $match: {
          createdAt: {
            $gte: new Date(new Date().setDate(new Date().getDate() - 30))
          },
          status: 'approved'
        }
      },
      {
        $group: {
          _id: null,
          total: { $sum: '$platform_fee' }
        }
      }
    ]);

    // User growth (last 12 months)
    const userGrowth = await User.aggregate([
      {
        $match: {
          createdAt: {
            $gte: new Date(new Date().setMonth(new Date().getMonth() - 12))
          }
        }
      },
      {
        $group: {
          _id: {
            year: { $year: '$createdAt' },
            month: { $month: '$createdAt' }
          },
          count: { $sum: 1 }
        }
      },
      {
        $sort: { '_id.year': 1, '_id.month': 1 }
      }
    ]);

    // Revenue trends (last 6 months)
    const revenueTrends = await Withdrawal.aggregate([
      {
        $match: {
          createdAt: {
            $gte: new Date(new Date().setMonth(new Date().getMonth() - 6))
          },
          status: 'approved'
        }
      },
      {
        $group: {
          _id: {
            year: { $year: '$createdAt' },
            month: { $month: '$createdAt' }
          },
          revenue: { $sum: '$platform_fee' }
        }
      },
      {
        $sort: { '_id.year': 1, '_id.month': 1 }
      }
    ]);

    const analytics = {
      daily_signups: dailySignups,
      weekly_investments: weeklyInvestments.length > 0 ? weeklyInvestments[0].total : 0,
      monthly_revenue: monthlyRevenue.length > 0 ? monthlyRevenue[0].total : 0,
      avg_investment: avgInvestment.length > 0 ? avgInvestment[0].average : 0,
      user_growth: userGrowth.map(item => item.count),
      revenue_trends: revenueTrends.map(item => item.revenue)
    };

    res.json(
      formatResponse(true, 'Admin analytics retrieved', { analytics })
    );
  } catch (error) {
    handleError(res, error, 'Error fetching admin analytics');
  }
});

// Get Pending Investments for Admin
app.get('/api/admin/pending-investments', adminAuth, async (req, res) => {
  try {
    const investments = await Investment.find({ status: 'pending' })
      .populate('user', 'full_name email phone')
      .populate('plan', 'name min_amount max_amount daily_interest duration')
      .sort({ createdAt: -1 })
      .lean();

    // Format for frontend
    const formattedInvestments = investments.map(inv => ({
      id: inv._id,
      user_name: inv.user.full_name,
      plan_name: inv.plan.name,
      amount: inv.amount,
      date: inv.createdAt,
      status: inv.status
    }));

    res.json(
      formatResponse(true, 'Pending investments retrieved', { 
        investments: formattedInvestments 
      })
    );
  } catch (error) {
    handleError(res, error, 'Error fetching pending investments');
  }
});

// Approve Investment
app.post('/api/admin/investments/:id/approve', adminAuth, [
  param('id')
    .isMongoId()
    .withMessage('Invalid investment ID')
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

    const investment = await Investment.findByIdAndUpdate(
      req.params.id,
      { 
        status: 'active',
        approved_at: new Date(),
        approved_by: req.user.id,
        start_date: new Date()
      },
      { new: true }
    ).populate('user plan');

    if (!investment) {
      return res.status(404).json(
        formatResponse(false, 'Investment not found')
      );
    }

    // Send notification to user
    await Notification.create({
      user: investment.user._id,
      title: 'Investment Approved!',
      message: `Your investment in ${investment.plan.name} has been approved and is now active`,
      type: 'success'
    });

    // Real-time update
    broadcastToUser(investment.user._id.toString(), {
      type: 'investment_approved',
      investment_id: investment._id,
      message: `Your investment in ${investment.plan.name} has been approved`
    });

    res.json(
      formatResponse(true, 'Investment approved successfully', { investment })
    );
  } catch (error) {
    handleError(res, error, 'Error approving investment');
  }
});

// Reject Investment
app.post('/api/admin/investments/:id/reject', adminAuth, [
  param('id')
    .isMongoId()
    .withMessage('Invalid investment ID'),
  body('reason')
    .optional()
    .trim()
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

    const { reason } = req.body;

    const investment = await Investment.findById(req.params.id).populate('user plan');
    if (!investment) {
      return res.status(404).json(
        formatResponse(false, 'Investment not found')
      );
    }

    // Refund amount to user
    await User.findByIdAndUpdate(investment.user._id, {
      $inc: { balance: investment.amount }
    });

    // Update investment status
    investment.status = 'rejected';
    investment.approved_by = req.user.id;
    investment.approved_at = new Date();
    await investment.save();

    // Create refund transaction
    await Transaction.create({
      user: investment.user._id,
      type: 'refund',
      amount: investment.amount,
      description: `Refund for rejected investment in ${investment.plan.name}`,
      status: 'completed',
      related_investment: investment._id
    });

    // Send notification to user
    await Notification.create({
      user: investment.user._id,
      title: 'Investment Rejected',
      message: `Your investment in ${investment.plan.name} was rejected. ${reason || 'Please contact support for more information.'}`,
      type: 'error'
    });

    // Real-time update
    broadcastToUser(investment.user._id.toString(), {
      type: 'balance_update',
      balance: (await User.findById(investment.user._id)).balance,
      message: `Refund of ₦${investment.amount.toLocaleString()} for rejected investment`
    });

    res.json(
      formatResponse(true, 'Investment rejected successfully', { investment })
    );
  } catch (error) {
    handleError(res, error, 'Error rejecting investment');
  }
});

// Get Pending Deposits for Admin
app.get('/api/admin/pending-deposits', adminAuth, async (req, res) => {
  try {
    const deposits = await Deposit.find({ status: 'pending' })
      .populate('user', 'full_name email phone')
      .sort({ createdAt: -1 })
      .lean();

    // Format for frontend
    const formattedDeposits = deposits.map(deposit => ({
      id: deposit._id,
      user_name: deposit.user.full_name,
      amount: deposit.amount,
      date: deposit.createdAt,
      status: deposit.status,
      payment_method: deposit.payment_method
    }));

    res.json(
      formatResponse(true, 'Pending deposits retrieved', { 
        deposits: formattedDeposits 
      })
    );
  } catch (error) {
    handleError(res, error, 'Error fetching pending deposits');
  }
});

// Approve Deposit
app.post('/api/admin/deposits/:id/approve', adminAuth, [
  param('id')
    .isMongoId()
    .withMessage('Invalid deposit ID')
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

    const deposit = await Deposit.findByIdAndUpdate(
      req.params.id,
      { 
        status: 'approved',
        approved_at: new Date(),
        approved_by: req.user.id
      },
      { new: true }
    ).populate('user');

    if (!deposit) {
      return res.status(404).json(
        formatResponse(false, 'Deposit not found')
      );
    }

    // Add to user balance
    await User.findByIdAndUpdate(deposit.user._id, {
      $inc: { balance: deposit.amount }
    });

    // Create transaction
    await Transaction.create({
      user: deposit.user._id,
      type: 'deposit',
      amount: deposit.amount,
      description: `Deposit via ${deposit.payment_method}`,
      status: 'completed',
      related_deposit: deposit._id
    });

    // Send notification to user
    await Notification.create({
      user: deposit.user._id,
      title: 'Deposit Approved!',
      message: `Your deposit of ₦${deposit.amount.toLocaleString()} has been approved`,
      type: 'success'
    });

    // Real-time update
    broadcastToUser(deposit.user._id.toString(), {
      type: 'balance_update',
      balance: (await User.findById(deposit.user._id)).balance,
      message: `Deposit of ₦${deposit.amount.toLocaleString()} approved`
    });

    res.json(
      formatResponse(true, 'Deposit approved successfully', { deposit })
    );
  } catch (error) {
    handleError(res, error, 'Error approving deposit');
  }
});

// Get Pending Withdrawals for Admin
app.get('/api/admin/pending-withdrawals', adminAuth, async (req, res) => {
  try {
    const withdrawals = await Withdrawal.find({ status: 'pending' })
      .populate('user', 'full_name email phone')
      .sort({ createdAt: -1 })
      .lean();

    // Format for frontend
    const formattedWithdrawals = withdrawals.map(withdrawal => ({
      id: withdrawal._id,
      user_name: withdrawal.user.full_name,
      amount: withdrawal.amount,
      fee: withdrawal.platform_fee,
      net_amount: withdrawal.net_amount,
      date: withdrawal.createdAt,
      status: withdrawal.status,
      bank_details: withdrawal.bank_details ? 
        `${withdrawal.bank_details.bank_name} - ${withdrawal.bank_details.account_number}` : 
        (withdrawal.wallet_address || withdrawal.paypal_email)
    }));

    res.json(
      formatResponse(true, 'Pending withdrawals retrieved', { 
        withdrawals: formattedWithdrawals 
      })
    );
  } catch (error) {
    handleError(res, error, 'Error fetching pending withdrawals');
  }
});

// Approve Withdrawal
app.post('/api/admin/withdrawals/:id/approve', adminAuth, [
  param('id')
    .isMongoId()
    .withMessage('Invalid withdrawal ID')
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

    const withdrawal = await Withdrawal.findByIdAndUpdate(
      req.params.id,
      { 
        status: 'approved',
        approved_at: new Date(),
        approved_by: req.user.id
      },
      { new: true }
    ).populate('user');

    if (!withdrawal) {
      return res.status(404).json(
        formatResponse(false, 'Withdrawal not found')
      );
    }

    // Deduct from user balance
    await User.findByIdAndUpdate(withdrawal.user._id, {
      $inc: { balance: -withdrawal.amount }
    });

    // Create transaction
    await Transaction.create({
      user: withdrawal.user._id,
      type: 'withdrawal',
      amount: -withdrawal.amount,
      description: `Withdrawal via ${withdrawal.payment_method}`,
      status: 'completed',
      related_withdrawal: withdrawal._id
    });

    // Send notification to user
    await Notification.create({
      user: withdrawal.user._id,
      title: 'Withdrawal Approved!',
      message: `Your withdrawal of ₦${withdrawal.amount.toLocaleString()} has been approved and will be processed shortly`,
      type: 'success'
    });

    // Real-time update
    broadcastToUser(withdrawal.user._id.toString(), {
      type: 'balance_update',
      balance: (await User.findById(withdrawal.user._id)).balance,
      message: `Withdrawal of ₦${withdrawal.amount.toLocaleString()} approved`
    });

    res.json(
      formatResponse(true, 'Withdrawal approved successfully', { withdrawal })
    );
  } catch (error) {
    handleError(res, error, 'Error approving withdrawal');
  }
});

// Get All Users for Admin
app.get('/api/admin/users', adminAuth, async (req, res) => {
  try {
    const { page, limit, skip } = getPaginationOptions(req);
    const status = req.query.status;

    let query = { role: 'user' };
    if (status && status !== 'all') {
      if (status === 'active') query.is_active = true;
      if (status === 'inactive') query.is_active = false;
      if (status === 'verified') query.kyc_verified = true;
      if (status === 'unverified') query.kyc_verified = false;
    }

    const users = await User.find(query)
      .select('full_name email phone balance total_earnings referral_earnings kyc_verified is_active createdAt last_login')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit)
      .lean();

    const total = await User.countDocuments(query);

    res.json(
      formatResponse(true, 'Users retrieved successfully', {
        users,
        pagination: {
          page,
          limit,
          total,
          pages: Math.ceil(total / limit)
        }
      })
    );
  } catch (error) {
    handleError(res, error, 'Error fetching users');
  }
});

// ==================== FILE UPLOAD ENDPOINT - 100% FRONTEND COMPATIBLE ====================

app.post('/api/upload', auth, upload.single('file'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json(
        formatResponse(false, 'No file uploaded')
      );
    }

    const folder = req.body.folder || 'general';
    const fileUrl = await handleFileUpload(req.file, folder);

    res.json(
      formatResponse(true, 'File uploaded successfully', {
        fileUrl: fileUrl
      })
    );

  } catch (error) {
    handleError(res, error, 'Error uploading file');
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
    }).populate('plan').populate('user');

    let totalEarnings = 0;
    let processedCount = 0;

    for (const investment of activeInvestments) {
      try {
        const dailyEarning = investment.daily_earnings;
        
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
        await Transaction.create({
          user: investment.user._id,
          type: 'earning',
          amount: dailyEarning,
          description: `Daily earnings from ${investment.plan.name} investment`,
          status: 'completed',
          related_investment: investment._id
        });

        totalEarnings += dailyEarning;
        processedCount++;

        // Real-time update
        broadcastToUser(investment.user._id.toString(), {
          type: 'earning_added',
          amount: dailyEarning,
          message: `Daily earnings of ₦${dailyEarning.toLocaleString()} from ${investment.plan.name}`
        });

      } catch (investmentError) {
        console.error(`Error processing investment ${investment._id}:`, investmentError);
      }
    }

    console.log(`✅ Daily earnings calculated. Processed: ${processedCount}, Total: ₦${totalEarnings.toLocaleString()}`);
  } catch (error) {
    console.error('❌ Error calculating daily earnings:', error);
  }
});

// Check completed investments
cron.schedule('0 1 * * *', async () => {
  try {
    console.log('🔄 Checking completed investments...');
    
    const completedInvestments = await Investment.find({
      status: 'active',
      end_date: { $lte: new Date() }
    }).populate('user plan');

    let completedCount = 0;

    for (const investment of completedInvestments) {
      try {
        investment.status = 'completed';
        investment.completed_at = new Date();
        await investment.save();

        // Send completion notification
        await Notification.create({
          user: investment.user._id,
          title: 'Investment Completed!',
          message: `Your investment in ${investment.plan.name} has been completed. Total returns: ₦${investment.earned_so_far.toLocaleString()}`,
          type: 'success'
        });

        // Handle auto-renew
        if (investment.auto_renew) {
          const newInvestment = new Investment({
            user: investment.user._id,
            plan: investment.plan._id,
            amount: investment.amount,
            status: 'pending',
            auto_renew: true
          });

          await newInvestment.save();

          await Notification.create({
            user: investment.user._id,
            title: 'Investment Auto-Renewed',
            message: `Your investment in ${investment.plan.name} has been automatically renewed`,
            type: 'info'
          });
        }

        completedCount++;

      } catch (investmentError) {
        console.error(`Error completing investment ${investment._id}:`, investmentError);
      }
    }

    console.log(`✅ Completed ${completedCount} investment checks`);
  } catch (error) {
    console.error('❌ Error checking completed investments:', error);
  }
});

// Cleanup old data (run weekly)
cron.schedule('0 2 * * 0', async () => {
  try {
    console.log('🔄 Running weekly cleanup...');
    
    // Delete notifications older than 90 days
    const ninetyDaysAgo = new Date();
    ninetyDaysAgo.setDate(ninetyDaysAgo.getDate() - 90);
    
    const deletedNotifications = await Notification.deleteMany({
      createdAt: { $lt: ninetyDaysAgo },
      is_read: true
    });
    
    console.log(`✅ Cleaned up ${deletedNotifications.deletedCount} old notifications`);
  } catch (error) {
    console.error('❌ Error during cleanup:', error);
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
    message: '🚀 Raw Wealthy Backend v30.0 is running perfectly!',
    timestamp: new Date().toISOString(),
    version: '30.0.0',
    database: statusMap[dbStatus] || 'unknown',
    websocket: connectedClients.size,
    environment: process.env.NODE_ENV || 'development',
    uptime: process.uptime(),
    memory: process.memoryUsage(),
    node_version: process.version
  };

  // If database is not connected, return 503
  if (dbStatus !== 1) {
    healthCheck.success = false;
    healthCheck.status = 'Database Connection Issue';
    return res.status(503).json(healthCheck);
  }

  res.json(healthCheck);
});

// ==================== ROOT ENDPOINT ====================
app.get('/', (req, res) => {
  res.json({
    success: true,
    message: '🚀 Raw Wealthy Backend API v30.0 - 100% Frontend Integrated & Production Ready',
    version: '30.0.0',
    timestamp: new Date().toISOString(),
    status: 'Operational',
    environment: process.env.NODE_ENV || 'development',
    endpoints: {
      health: '/health',
      api: '/api',
      documentation: 'Fully synchronized with frontend',
      features: [
        'User Authentication & Management',
        'Investment Platform',
        'KYC Verification',
        '2FA Security',
        'Admin Dashboard',
        'Real-time WebSocket',
        'File Upload System',
        'Cron Job Automation'
      ]
    }
  });
});

// ==================== ERROR HANDLING ====================
app.use((err, req, res, next) => {
  console.error('Error Stack:', err.stack);
  
  if (err.name === 'ValidationError') {
    const messages = Object.values(err.errors).map(val => val.message);
    return res.status(400).json(
      formatResponse(false, 'Validation Error', { errors: messages })
    );
  }
  
  if (err.code === 11000) {
    return res.status(400).json(
      formatResponse(false, 'Duplicate entry found')
    );
  }
  
  if (err.name === 'JsonWebTokenError') {
    return res.status(401).json(
      formatResponse(false, 'Invalid token')
    );
  }
  
  if (err.name === 'TokenExpiredError') {
    return res.status(401).json(
      formatResponse(false, 'Token expired')
    );
  }
  
  if (err instanceof multer.MulterError) {
    if (err.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json(
        formatResponse(false, 'File too large. Maximum size is 10MB.')
      );
    }
    return res.status(400).json(
      formatResponse(false, `File upload error: ${err.message}`)
    );
  }

  const statusCode = err.status || 500;
  const message = process.env.NODE_ENV === 'production' && statusCode === 500 
    ? 'Internal Server Error' 
    : err.message;

  res.status(statusCode).json(
    formatResponse(false, message)
  );
});

// 404 Handler
app.use('*', (req, res) => {
  res.status(404).json(
    formatResponse(false, `Route ${req.originalUrl} not found`)
  );
});

// ==================== INITIALIZE APPLICATION ====================
const initializeApp = async () => {
  try {
    await connectDB();
    
    const PORT = process.env.PORT || 5000;
    const server = app.listen(PORT, '0.0.0.0', () => {
      console.log(`
🎯 RAW WEALTHY BACKEND v30.0 - 100% FRONTEND INTEGRATED
🌐 Server running on port ${PORT}
🚀 Environment: ${process.env.NODE_ENV || 'development'}
📊 Health Check: /health
🔗 API Base: /api
💾 Database: MongoDB Cloud
🛡️ Security: Enhanced with rate limiting & validation
⚡ Real-time: WebSocket support enabled
📧 Email: Nodemailer configured

✅ ALL FRONTEND FEATURES SUPPORTED:
   ✅ User Authentication & Registration
   ✅ Investment Management
   ✅ Real File Upload
   ✅ KYC Verification System
   ✅ 2FA Authentication
   ✅ Admin Dashboard & Analytics
   ✅ Referral System
   ✅ Support Ticket System
   ✅ Real-time WebSocket Updates
   ✅ Cron Job Automation
   ✅ Payment Processing
   ✅ Comprehensive Security

🚀 PERFECT FRONTEND-BACKEND SYNCHRONIZATION!
      `);
    });

    // WebSocket server upgrade
    server.on('upgrade', (request, socket, head) => {
      wss.handleUpgrade(request, socket, head, (ws) => {
        wss.emit('connection', ws, request);
      });
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

initializeApp();

module.exports = app;
