// server.js - ULTIMATE PRODUCTION READY RAW WEALTHY BACKEND v12.0
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
require('dotenv').config();

const app = express();

// ==================== ENHANCED CLOUDINARY CONFIGURATION ====================
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME || 'dyotuz5h7',
  api_key: process.env.CLOUDINARY_API_KEY || '775719636564583',
  api_secret: process.env.CLOUDINARY_API_SECRET || '-8o6zGglkQhyX-Bs9e5Ug_MSUm4'
});

// ==================== ULTIMATE SECURITY MIDDLEWARE ====================
app.use(helmet({
  crossOriginResourcePolicy: { policy: "cross-origin" },
  contentSecurityPolicy: false
}));
app.use(mongoSanitize());

// ==================== PERFECT CORS CONFIGURATION ====================
app.use(cors({
  origin: [
    "https://real-earning.vercel.app",
    "https://real-earning.vercel.app/",
    "http://localhost:3000",
    "http://127.0.0.1:5500",
    "http://localhost:5500"
  ],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Accept', 'Origin']
}));

// Handle preflight requests
app.options('*', cors());

// ==================== ENHANCED RATE LIMITING ====================
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 50,
  message: { success: false, message: 'Too many authentication attempts' }
});

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 500,
  message: { success: false, message: 'Too many requests' }
});

app.use('/api/auth/', authLimiter);
app.use('/api/', apiLimiter);

// ==================== ENHANCED COMPRESSION & LOGGING ====================
app.use(compression());
app.use(morgan('combined'));

// ==================== PERFECT BODY PARSING ====================
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

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
    cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
  }
});

const fileFilter = (req, file, cb) => {
  if (file.mimetype.startsWith('image/') || file.mimetype.startsWith('application/')) {
    cb(null, true);
  } else {
    cb(new Error('Only image and document files are allowed!'), false);
  }
};

const upload = multer({
  storage: storage,
  fileFilter: fileFilter,
  limits: {
    fileSize: 10 * 1024 * 1024 // 10MB limit
  }
});

// ==================== ENHANCED STATIC FILES ====================
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// ==================== REDIS CACHE SETUP WITH FALLBACK ====================
let redisClient;
const initializeRedis = async () => {
  try {
    redisClient = redis.createClient({
      url: process.env.REDIS_URL || 'redis://localhost:6379',
      socket: {
        connectTimeout: 60000,
        lazyConnect: true
      }
    });

    redisClient.on('error', (err) => {
      console.log('⚠️ Redis Connection Error (Using Fallback):', err.message);
    });

    redisClient.on('connect', () => {
      console.log('✅ Redis Connected Successfully');
    });

    await redisClient.connect();
    return true;
  } catch (error) {
    console.log('❌ Redis Connection Failed - Using In-Memory Fallback');
    
    // Create in-memory fallback
    redisClient = {
      data: new Map(),
      isOpen: true,
      get: async (key) => redisClient.data.get(key),
      setEx: async (key, expiry, value) => {
        redisClient.data.set(key, value);
        setTimeout(() => redisClient.data.delete(key), expiry * 1000);
      },
      del: async (key) => redisClient.data.delete(key),
      set: async (key, value) => redisClient.data.set(key, value),
      quit: async () => { /* No-op for fallback */ }
    };
    return false;
  }
};

// ==================== WEBSOCKET SETUP ====================
const wss = new WebSocket.Server({ noServer: true });
const connectedClients = new Map();

wss.on('connection', (ws, request) => {
  const userId = request.headers['user-id'];
  if (userId) {
    connectedClients.set(userId, ws);
    console.log(`✅ User ${userId} connected via WebSocket`);
  }

  ws.on('close', () => {
    if (userId) {
      connectedClients.delete(userId);
      console.log(`❌ User ${userId} disconnected`);
    }
  });
});

// WebSocket broadcast function
const broadcastToUser = (userId, data) => {
  const client = connectedClients.get(userId);
  if (client && client.readyState === WebSocket.OPEN) {
    client.send(JSON.stringify(data));
  }
};

// ==================== ENHANCED EMAIL CONFIGURATION ====================
const createEmailTransporter = () => {
  try {
    return nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
      }
    });
  } catch (error) {
    console.log('⚠️ Email transporter creation failed:', error.message);
    return null;
  }
};

const emailTransporter = createEmailTransporter();

// ==================== ENHANCED DATABASE CONNECTION ====================
const connectDB = async () => {
  try {
    const MONGODB_URI = process.env.MONGODB_URI || 'MONGODB_URI=mongodb+srv://Rawmoney:rawmoney@rawwealthy.mwxlqha.mongodb.net/rawwealthy?retryWrites=true&w=majority&socketTimeoutMS=30000&connectTimeoutMS=30000&serverSelectionTimeoutMS=30000';
    
    if (!MONGODB_URI) {
      throw new Error('MONGODB_URI environment variable is required');
    }
    
    // Enhanced connection options for production
    await mongoose.connect(MONGODB_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
      serverSelectionTimeoutMS: 30000,
      socketTimeoutMS: 45000,
      maxPoolSize: 10,
      retryWrites: true,
      w: 'majority'
    });
    
    console.log('✅ MongoDB Connected Successfully');
    
    // Initialize database with enhanced sample data
    await initializeDatabase();
  } catch (error) {
    console.error('❌ MongoDB Connection Error:', error.message);
    
    if (error.name === 'MongooseServerSelectionError') {
      console.log('💡 Solution: Please check your MongoDB Atlas IP whitelist and connection string');
      console.log('🔗 Whitelist Guide: https://www.mongodb.com/docs/atlas/security-whitelist/');
    }
    
    // Retry connection after 10 seconds
    setTimeout(connectDB, 10000);
  }
};

// ==================== ENHANCED DATABASE MODELS ====================

// Enhanced User Model
const userSchema = new mongoose.Schema({
  full_name: { type: String, required: true },
  email: { type: String, required: true, unique: true, index: true },
  phone: { type: String, required: true },
  password: { type: String, required: true },
  role: { type: String, enum: ['user', 'admin'], default: 'user' },
  balance: { type: Number, default: 0 },
  total_earnings: { type: Number, default: 0 },
  referral_earnings: { type: Number, default: 0 },
  referral_code: { type: String, unique: true, index: true },
  referred_by: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  kyc_verified: { type: Boolean, default: false },
  kyc_documents: {
    id_type: String,
    id_number: String,
    id_front: String,
    id_back: String,
    selfie_with_id: String,
    status: { type: String, enum: ['pending', 'approved', 'rejected'], default: 'pending' },
    submitted_at: Date,
    reviewed_at: Date,
    reviewed_by: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }
  },
  risk_tolerance: { type: String, enum: ['low', 'medium', 'high'], default: 'medium' },
  investment_strategy: { type: String, enum: ['conservative', 'balanced', 'aggressive'], default: 'balanced' },
  two_factor_enabled: { type: Boolean, default: false },
  two_factor_secret: String,
  is_active: { type: Boolean, default: true },
  last_login: Date,
  login_attempts: { type: Number, default: 0 },
  lock_until: Date,
  bank_details: {
    bank_name: String,
    account_name: String,
    account_number: String,
    verified: { type: Boolean, default: false }
  },
  preferences: {
    currency: { type: String, default: 'NGN' },
    language: { type: String, default: 'en' },
    timezone: { type: String, default: 'Africa/Lagos' },
    email_notifications: { type: Boolean, default: true },
    sms_notifications: { type: Boolean, default: true },
    push_notifications: { type: Boolean, default: true }
  }
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

userSchema.virtual('isLocked').get(function() {
  return !!(this.lock_until && this.lock_until > Date.now());
});

userSchema.pre('save', async function(next) {
  if (this.isModified('password')) {
    this.password = await bcrypt.hash(this.password, 12);
  }
  if (!this.referral_code) {
    this.referral_code = Math.random().toString(36).substr(2, 8).toUpperCase();
  }
  next();
});

userSchema.methods.comparePassword = async function(password) {
  if (this.isLocked) {
    throw new Error('Account is temporarily locked due to too many login attempts');
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

userSchema.methods.generate2FASecret = function() {
  const secret = speakeasy.generateSecret({
    name: `RawWealthy (${this.email})`
  });
  this.two_factor_secret = secret.base32;
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

const User = mongoose.model('User', userSchema);

// Enhanced Investment Plan Model
const investmentPlanSchema = new mongoose.Schema({
  name: { type: String, required: true },
  description: { type: String, required: true },
  min_amount: { type: Number, required: true },
  max_amount: { type: Number },
  daily_interest: { type: Number, required: true },
  total_interest: { type: Number, required: true },
  duration: { type: Number, required: true },
  risk_level: { type: String, enum: ['low', 'medium', 'high'], required: true },
  is_popular: { type: Boolean, default: false },
  raw_material: { type: String, required: true },
  is_active: { type: Boolean, default: true },
  features: [String],
  image_url: String,
  category: { type: String, enum: ['agriculture', 'mining', 'energy', 'metals'], default: 'agriculture' }
}, { 
  timestamps: true,
  toJSON: { virtuals: true }
});

investmentPlanSchema.virtual('estimated_earnings').get(function() {
  return (this.min_amount * this.total_interest) / 100;
});

const InvestmentPlan = mongoose.model('InvestmentPlan', investmentPlanSchema);

// Enhanced Investment Model
const investmentSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  plan: { type: mongoose.Schema.Types.ObjectId, ref: 'InvestmentPlan', required: true },
  amount: { type: Number, required: true, min: [1000, 'Minimum investment is ₦1000'] },
  status: { type: String, enum: ['pending', 'active', 'completed', 'cancelled'], default: 'pending', index: true },
  start_date: { type: Date, default: Date.now },
  end_date: { type: Date, required: true },
  expected_earnings: { type: Number, required: true },
  earned_so_far: { type: Number, default: 0 },
  daily_earnings: { type: Number, default: 0 },
  auto_renew: { type: Boolean, default: false },
  payment_proof: { type: String },
  transaction_hash: String,
  admin_notes: String,
  approved_by: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  approved_at: Date
}, { 
  timestamps: true,
  toJSON: { virtuals: true }
});

investmentSchema.virtual('remaining_days').get(function() {
  if (this.status !== 'active') return 0;
  const now = new Date();
  const end = new Date(this.end_date);
  const diffTime = end - now;
  const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));
  return Math.max(0, diffDays);
});

investmentSchema.virtual('total_earned').get(function() {
  return this.earned_so_far;
});

investmentSchema.virtual('is_expired').get(function() {
  return this.status === 'active' && new Date() > this.end_date;
});

investmentSchema.pre('save', async function(next) {
  if (this.isModified('plan') && this.plan) {
    const plan = await InvestmentPlan.findById(this.plan);
    if (plan) {
      const endDate = new Date(this.start_date);
      endDate.setDate(endDate.getDate() + plan.duration);
      this.end_date = endDate;
      
      this.expected_earnings = (this.amount * plan.total_interest) / 100;
      this.daily_earnings = (this.amount * plan.daily_interest) / 100;
    }
  }
  next();
});

const Investment = mongoose.model('Investment', investmentSchema);

// Enhanced Deposit Model
const depositSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  amount: { type: Number, required: true, min: [500, 'Minimum deposit is ₦500'] },
  payment_method: { type: String, enum: ['bank_transfer', 'crypto', 'paypal', 'card'], required: true },
  status: { type: String, enum: ['pending', 'approved', 'rejected'], default: 'pending', index: true },
  payment_proof: { type: String },
  transaction_hash: String,
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
    transaction_hash: String
  }
}, { 
  timestamps: true,
  toJSON: { virtuals: true }
});

depositSchema.post('findOneAndUpdate', async function(doc) {
  if (doc && this.getUpdate().$set && this.getUpdate().$set.status === 'approved' && doc.status !== 'approved') {
    await User.findByIdAndUpdate(doc.user, { $inc: { balance: doc.amount } });
    
    await Transaction.create({
      user: doc.user,
      type: 'deposit',
      amount: doc.amount,
      description: `Deposit via ${doc.payment_method}`,
      status: 'completed'
    });

    // Clear user cache
    await redisClient.del(`user:${doc.user}`);
    
    // Send real-time notification
    broadcastToUser(doc.user.toString(), {
      type: 'balance_update',
      balance: (await User.findById(doc.user)).balance
    });

    // Send email notification
    const user = await User.findById(doc.user);
    await sendEmail(
      user.email,
      'Deposit Approved - Raw Wealthy',
      `Your deposit of ₦${doc.amount.toLocaleString()} has been approved and credited to your account.`
    );
  }
});

const Deposit = mongoose.model('Deposit', depositSchema);

// Enhanced Withdrawal Model
const withdrawalSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  amount: { type: Number, required: true, min: [1000, 'Minimum withdrawal is ₦1000'] },
  platform_fee: { type: Number, default: 0 },
  net_amount: { type: Number, required: true },
  payment_method: { type: String, enum: ['bank_transfer', 'crypto', 'paypal'], required: true },
  bank_details: {
    bank_name: String,
    account_name: String,
    account_number: String
  },
  wallet_address: String,
  paypal_email: String,
  status: { type: String, enum: ['pending', 'approved', 'rejected', 'processing'], default: 'pending', index: true },
  admin_notes: String,
  approved_by: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  approved_at: Date,
  processed_at: Date
}, { 
  timestamps: true,
  toJSON: { virtuals: true }
});

withdrawalSchema.pre('save', function(next) {
  if (this.isModified('amount')) {
    this.platform_fee = this.amount * 0.05; // 5% platform fee
    this.net_amount = this.amount - this.platform_fee;
  }
  next();
});

withdrawalSchema.post('findOneAndUpdate', async function(doc) {
  if (doc && this.getUpdate().$set && this.getUpdate().$set.status === 'approved' && doc.status !== 'approved') {
    await User.findByIdAndUpdate(doc.user, { $inc: { balance: -doc.amount } });
    
    await Transaction.create({
      user: doc.user,
      type: 'withdrawal',
      amount: -doc.amount,
      description: `Withdrawal via ${doc.payment_method} (Fee: ₦${doc.platform_fee})`,
      status: 'completed'
    });

    // Clear user cache
    await redisClient.del(`user:${doc.user}`);
    
    // Send real-time notification
    broadcastToUser(doc.user.toString(), {
      type: 'balance_update',
      balance: (await User.findById(doc.user)).balance
    });

    // Send email notification
    const user = await User.findById(doc.user);
    await sendEmail(
      user.email,
      'Withdrawal Approved - Raw Wealthy',
      `Your withdrawal request of ₦${doc.amount.toLocaleString()} has been approved. Net amount: ₦${doc.net_amount.toLocaleString()}.`
    );
  }
});

const Withdrawal = mongoose.model('Withdrawal', withdrawalSchema);

// Enhanced Transaction Model
const transactionSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  type: { type: String, enum: ['deposit', 'withdrawal', 'investment', 'earning', 'referral', 'bonus', 'fee'], required: true },
  amount: { type: Number, required: true },
  description: { type: String, required: true },
  status: { type: String, enum: ['pending', 'completed', 'failed'], default: 'completed' },
  reference: { type: String, unique: true, index: true },
  metadata: mongoose.Schema.Types.Mixed,
  related_investment: { type: mongoose.Schema.Types.ObjectId, ref: 'Investment' },
  related_deposit: { type: mongoose.Schema.Types.ObjectId, ref: 'Deposit' },
  related_withdrawal: { type: mongoose.Schema.Types.ObjectId, ref: 'Withdrawal' }
}, { 
  timestamps: true,
  toJSON: { virtuals: true }
});

transactionSchema.pre('save', function(next) {
  if (!this.reference) {
    this.reference = `TXN${Date.now()}${Math.random().toString(36).substr(2, 9)}`.toUpperCase();
  }
  next();
});

const Transaction = mongoose.model('Transaction', transactionSchema);

// Enhanced KYC Model
const kycSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  id_type: { type: String, enum: ['national_id', 'passport', 'driver_license'], required: true },
  id_number: { type: String, required: true },
  id_front: { type: String, required: true },
  id_back: { type: String, required: true },
  selfie_with_id: { type: String, required: true },
  status: { type: String, enum: ['pending', 'approved', 'rejected'], default: 'pending', index: true },
  admin_notes: String,
  reviewed_by: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  reviewed_at: Date
}, { 
  timestamps: true,
  toJSON: { virtuals: true }
});

const KYC = mongoose.model('KYC', kycSchema);

// Enhanced Notification Model
const notificationSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  title: { type: String, required: true },
  message: { type: String, required: true },
  type: { type: String, enum: ['info', 'success', 'warning', 'error'], default: 'info' },
  is_read: { type: Boolean, default: false },
  action_url: String,
  related_model: String,
  related_id: mongoose.Schema.Types.ObjectId
}, { 
  timestamps: true,
  toJSON: { virtuals: true }
});

const Notification = mongoose.model('Notification', notificationSchema);

// Support Ticket Model
const supportTicketSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  subject: { type: String, required: true },
  message: { type: String, required: true },
  category: { type: String, enum: ['general', 'technical', 'investment', 'withdrawal', 'kyc', 'other'], default: 'general' },
  status: { type: String, enum: ['open', 'in_progress', 'resolved', 'closed'], default: 'open', index: true },
  priority: { type: String, enum: ['low', 'medium', 'high', 'urgent'], default: 'medium' },
  assigned_to: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  responses: [{
    message: String,
    replied_by: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    is_admin: { type: Boolean, default: false },
    attachments: [String],
    createdAt: { type: Date, default: Date.now }
  }],
  attachments: [String]
}, { 
  timestamps: true
});

const SupportTicket = mongoose.model('SupportTicket', supportTicketSchema);

// ==================== ENHANCED MIDDLEWARE ====================

// Enhanced Auth Middleware
const auth = async (req, res, next) => {
  try {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    
    if (!token) {
      return res.status(401).json({ success: false, message: 'No token, authorization denied' });
    }

    // Check Redis for token blacklist
    try {
      const isBlacklisted = await redisClient.get(`blacklist:${token}`);
      if (isBlacklisted) {
        return res.status(401).json({ success: false, message: 'Token has been invalidated' });
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

    const user = await User.findById(decoded.id);
    
    if (!user || !user.is_active) {
      return res.status(401).json({ success: false, message: 'Token is not valid or account is inactive' });
    }

    // Cache user for 5 minutes
    try {
      await redisClient.setEx(`user:${user._id}`, 300, JSON.stringify(user.toJSON()));
    } catch (cacheError) {
      console.log('⚠️ Cache write failed, continuing without cache');
    }
    
    req.user = user;
    next();
  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({ success: false, message: 'Token expired' });
    }
    if (error.name === 'JsonWebTokenError') {
      return res.status(401).json({ success: false, message: 'Invalid token' });
    }
    res.status(401).json({ success: false, message: 'Token is not valid' });
  }
};

// Enhanced Admin Auth Middleware
const adminAuth = async (req, res, next) => {
  try {
    await auth(req, res, () => {});
    if (req.user.role !== 'admin') {
      return res.status(403).json({ success: false, message: 'Access denied. Admin only.' });
    }
    next();
  } catch (error) {
    res.status(401).json({ success: false, message: 'Authentication failed' });
  }
};

// Enhanced KYC Middleware
const kycVerified = async (req, res, next) => {
  try {
    await auth(req, res, () => {});
    if (!req.user.kyc_verified) {
      return res.status(403).json({ 
        success: false, 
        message: 'KYC verification required for this action' 
      });
    }
    next();
  } catch (error) {
    res.status(401).json({ success: false, message: 'Authentication failed' });
  }
};

// ==================== ENHANCED UTILITY FUNCTIONS ====================

// Enhanced Email Service
const sendEmail = async (to, subject, text, html = null) => {
  try {
    if (!emailTransporter) {
      console.log('⚠️ Email transporter not available');
      return false;
    }

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: to,
      subject: subject,
      text: text,
      html: html || text
    };

    await emailTransporter.sendMail(mailOptions);
    console.log(`✅ Email sent to ${to}`);
    return true;
  } catch (error) {
    console.error('❌ Email sending error:', error);
    return false;
  }
};

// Enhanced Notification Service
const createNotification = async (userId, title, message, type = 'info', actionUrl = null, relatedModel = null, relatedId = null) => {
  try {
    const notification = await Notification.create({
      user: userId,
      title,
      message,
      type,
      action_url: actionUrl,
      related_model: relatedModel,
      related_id: relatedId
    });

    // Send real-time notification via WebSocket
    broadcastToUser(userId.toString(), {
      type: 'notification',
      notification: notification
    });

    return notification;
  } catch (error) {
    console.error('❌ Notification creation error:', error);
  }
};

// Enhanced Cache Helper
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
const formatResponse = (success, message, data = null, pagination = null) => {
  const response = {
    success,
    message,
    timestamp: new Date().toISOString()
  };
  
  if (data !== null) {
    response.data = data;
  }
  
  if (pagination !== null) {
    response.pagination = pagination;
  }
  
  return response;
};

// Enhanced Cloudinary File Upload Handler
const handleCloudinaryUpload = async (file, folder = 'rawwealthy') => {
  if (!file) return null;
  
  try {
    const result = await cloudinary.uploader.upload(file.path, {
      folder: folder,
      resource_type: 'auto',
      quality: 'auto',
      fetch_format: 'auto'
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
};

// Enhanced File Upload Handler with Cloudinary
const handleFileUpload = async (file, folder = 'general') => {
  if (!file) return null;
  
  // Use Cloudinary for production, local storage for development
  if (process.env.NODE_ENV === 'production') {
    return await handleCloudinaryUpload(file, `rawwealthy/${folder}`);
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

// ==================== ENHANCED DATABASE INITIALIZATION ====================
const initializeDatabase = async () => {
  try {
    // Check if admin exists
    const adminExists = await User.findOne({ email: 'admin@rawwealthy.com' });
    if (!adminExists) {
      const admin = new User({
        full_name: 'Raw Wealthy Admin',
        email: 'admin@rawwealthy.com',
        phone: '+2348000000001',
        password: 'Admin123!',
        role: 'admin',
        kyc_verified: true,
        balance: 0
      });
      await admin.save();
      console.log('✅ Admin user created');
    }

    // Check if plans exist
    const plansExist = await InvestmentPlan.countDocuments();
    if (plansExist === 0) {
      const plans = [
        {
          name: 'Cocoa Starter',
          description: 'Beginner-friendly cocoa investment with stable returns',
          min_amount: 3500,
          max_amount: 50000,
          daily_interest: 1.5,
          total_interest: 45,
          duration: 30,
          risk_level: 'low',
          is_popular: true,
          raw_material: 'Cocoa',
          category: 'agriculture',
          features: ['Low Risk', 'Stable Returns', 'Beginner Friendly', 'Daily Payouts']
        },
        {
          name: 'Gold Premium',
          description: 'Premium gold investment with higher returns',
          min_amount: 50000,
          max_amount: 500000,
          daily_interest: 2.5,
          total_interest: 75,
          duration: 30,
          risk_level: 'medium',
          is_popular: true,
          raw_material: 'Gold',
          category: 'metals',
          features: ['Medium Risk', 'Higher Returns', 'Portfolio Diversification', 'Daily Payouts']
        },
        {
          name: 'Crude Oil Pro',
          description: 'Professional crude oil investment portfolio',
          min_amount: 100000,
          max_amount: 1000000,
          daily_interest: 3.5,
          total_interest: 105,
          duration: 30,
          risk_level: 'high',
          is_popular: false,
          raw_material: 'Crude Oil',
          category: 'energy',
          features: ['High Risk', 'Maximum Returns', 'Professional Grade', 'Daily Payouts']
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

// ==================== PERFECTLY INTEGRATED ROUTES ====================

// Health Check with Enhanced Monitoring
app.get('/health', async (req, res) => {
  try {
    const dbStatus = mongoose.connection.readyState === 1 ? 'connected' : 'disconnected';
    const redisStatus = redisClient.isOpen ? 'connected' : 'disconnected';
    
    const totalUsers = await User.countDocuments();
    const totalInvestments = await Investment.countDocuments();
    const activeInvestments = await Investment.countDocuments({ status: 'active' });
    
    res.status(200).json({ 
      success: true,
      status: 'OK', 
      message: '🚀 Raw Wealthy Backend v12.0 is running perfectly!',
      timestamp: new Date().toISOString(),
      environment: process.env.NODE_ENV || 'development',
      version: '12.0.0',
      database: dbStatus,
      redis: redisStatus,
      cloudinary: 'configured',
      statistics: {
        total_users: totalUsers,
        total_investments: totalInvestments,
        active_investments: activeInvestments
      }
    });
  } catch (error) {
    res.status(500).json({ 
      success: false,
      status: 'ERROR',
      message: 'Health check failed',
      error: error.message 
    });
  }
});

// Root endpoint
app.get('/', (req, res) => {
  res.json({
    success: true,
    message: '🚀 Raw Wealthy Backend API v12.0 - Production Ready',
    version: '12.0.0',
    timestamp: new Date().toISOString(),
    endpoints: {
      health: '/health',
      api: '/api',
      docs: 'Coming soon...'
    }
  });
});

// ==================== AUTH ROUTES - FULLY INTEGRATED ====================

// Register Route
app.post('/api/register', [
  body('full_name').notEmpty().withMessage('Full name is required'),
  body('email').isEmail().withMessage('Valid email is required'),
  body('phone').notEmpty().withMessage('Phone number is required'),
  body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters'),
  body('referral_code').optional().isString(),
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
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json(formatResponse(false, 'User already exists with this email'));
    }

    // Check referral code
    let referredBy = null;
    if (referral_code) {
      referredBy = await User.findOne({ referral_code });
      if (!referredBy) {
        return res.status(400).json(formatResponse(false, 'Invalid referral code'));
      }
    }

    // Create user
    const user = new User({
      full_name,
      email,
      phone,
      password,
      referred_by: referredBy?._id,
      risk_tolerance: risk_tolerance || 'medium',
      investment_strategy: investment_strategy || 'balanced'
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
      `Dear ${full_name},\n\nWelcome to Raw Wealthy Investment Platform! Your account has been created successfully.\n\nStart your investment journey today and grow your wealth with our secure raw materials investment plans.\n\nBest regards,\nRaw Wealthy Team`
    );

    // Referral bonus if applicable
    if (referredBy) {
      const referralBonus = 1000; // ₦1000 referral bonus
      await User.findByIdAndUpdate(referredBy._id, {
        $inc: { 
          balance: referralBonus,
          referral_earnings: referralBonus
        }
      });

      await Transaction.create({
        user: referredBy._id,
        type: 'referral',
        amount: referralBonus,
        description: `Referral bonus for ${full_name}`,
        status: 'completed'
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
app.post('/api/login', [
  body('email').isEmail().withMessage('Valid email is required'),
  body('password').notEmpty().withMessage('Password is required')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json(formatResponse(false, 'Validation failed', { errors: errors.array() }));
    }

    const { email, password, two_factor_code } = req.body;

    // Find user
    const user = await User.findOne({ email });
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
          requires_2fa: true
        }));
      }

      const is2FATokenValid = user.verify2FAToken(two_factor_code);
      if (!is2FATokenValid) {
        return res.status(400).json(formatResponse(false, 'Invalid two-factor code'));
      }
    }

    // Update last login
    user.last_login = new Date();
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

// Logout Route
app.post('/api/logout', auth, async (req, res) => {
  try {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    if (token) {
      // Add token to blacklist with expiration
      try {
        const decoded = jwt.decode(token);
        const expiresIn = decoded.exp - Math.floor(Date.now() / 1000);
        if (expiresIn > 0) {
          await redisClient.setEx(`blacklist:${token}`, expiresIn, 'true');
        }
      } catch (blacklistError) {
        console.log('⚠️ Token blacklist failed');
      }
    }

    // Clear user cache
    await redisClient.del(`user:${req.user.id}`);

    res.json(formatResponse(true, 'Logged out successfully'));
  } catch (error) {
    console.error('Logout error:', error);
    res.status(500).json(formatResponse(false, 'Server error during logout'));
  }
});

// ==================== PROFILE ROUTES - FULLY INTEGRATED ====================

// Get Profile
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
    
    // Get recent transactions
    const recentTransactions = await Transaction.find({ user: req.user.id })
      .sort({ createdAt: -1 })
      .limit(5);
    
    // Get unread notifications count
    const unreadNotifications = await Notification.countDocuments({ 
      user: req.user.id, 
      is_read: false 
    });

    const profileData = {
      user,
      dashboard_stats: {
        active_investment_value: totalActiveValue,
        total_investments: activeInvestments.length,
        unread_notifications: unreadNotifications
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

// Update Profile
app.put('/api/profile', auth, [
  body('full_name').optional().notEmpty(),
  body('phone').optional().notEmpty(),
  body('risk_tolerance').optional().isIn(['low', 'medium', 'high']),
  body('investment_strategy').optional().isIn(['conservative', 'balanced', 'aggressive'])
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json(formatResponse(false, 'Validation failed', { errors: errors.array() }));
    }

    const { full_name, phone, risk_tolerance, investment_strategy } = req.body;
    
    const updateData = {};
    if (full_name) updateData.full_name = full_name;
    if (phone) updateData.phone = phone;
    if (risk_tolerance) updateData.risk_tolerance = risk_tolerance;
    if (investment_strategy) updateData.investment_strategy = investment_strategy;

    const user = await User.findByIdAndUpdate(
      req.user.id, 
      updateData, 
      { new: true }
    );

    // Clear cache
    await redisClient.del(`user:${req.user.id}`);
    await redisClient.del(`profile:${req.user.id}`);

    res.json(formatResponse(true, 'Profile updated successfully', { user }));
  } catch (error) {
    console.error('Profile update error:', error);
    res.status(500).json(formatResponse(false, 'Error updating profile'));
  }
});

// Change Password
app.put('/api/profile/password', auth, [
  body('current_password').notEmpty().withMessage('Current password is required'),
  body('new_password').isLength({ min: 6 }).withMessage('New password must be at least 6 characters')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json(formatResponse(false, 'Validation failed', { errors: errors.array() }));
    }

    const { current_password, new_password } = req.body;

    const user = await User.findById(req.user.id);
    const isMatch = await user.comparePassword(current_password);
    
    if (!isMatch) {
      return res.status(400).json(formatResponse(false, 'Current password is incorrect'));
    }

    user.password = new_password;
    await user.save();

    // Clear cache
    await redisClient.del(`user:${req.user.id}`);
    await redisClient.del(`profile:${req.user.id}`);

    res.json(formatResponse(true, 'Password updated successfully'));
  } catch (error) {
    console.error('Password change error:', error);
    res.status(500).json(formatResponse(false, 'Error changing password'));
  }
});

// ==================== 2FA ROUTES - FULLY INTEGRATED ====================

// Enable 2FA
app.post('/api/2fa/enable', auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    
    if (user.two_factor_enabled) {
      return res.status(400).json(formatResponse(false, '2FA is already enabled'));
    }

    const secret = user.generate2FASecret();
    await user.save();

    const qrCodeUrl = await QRCode.toDataURL(secret.otpauth_url);

    res.json(formatResponse(true, '2FA setup initiated', {
      secret: secret.base32,
      qrCode: qrCodeUrl
    }));
  } catch (error) {
    console.error('2FA enable error:', error);
    res.status(500).json(formatResponse(false, 'Error enabling 2FA'));
  }
});

// Verify 2FA Setup
app.post('/api/2fa/verify', auth, [
  body('token').notEmpty().withMessage('Token is required')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json(formatResponse(false, 'Validation failed', { errors: errors.array() }));
    }

    const { token } = req.body;
    const user = await User.findById(req.user.id);

    const isVerified = user.verify2FAToken(token);
    if (!isVerified) {
      return res.status(400).json(formatResponse(false, 'Invalid token'));
    }

    user.two_factor_enabled = true;
    await user.save();

    // Clear cache
    await redisClient.del(`user:${req.user.id}`);

    res.json(formatResponse(true, '2FA enabled successfully'));
  } catch (error) {
    console.error('2FA verify error:', error);
    res.status(500).json(formatResponse(false, 'Error verifying 2FA'));
  }
});

// Disable 2FA
app.post('/api/2fa/disable', auth, [
  body('token').notEmpty().withMessage('Token is required')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json(formatResponse(false, 'Validation failed', { errors: errors.array() }));
    }

    const { token } = req.body;
    const user = await User.findById(req.user.id);

    if (!user.two_factor_enabled) {
      return res.status(400).json(formatResponse(false, '2FA is not enabled'));
    }

    const isVerified = user.verify2FAToken(token);
    if (!isVerified) {
      return res.status(400).json(formatResponse(false, 'Invalid token'));
    }

    user.two_factor_enabled = false;
    user.two_factor_secret = undefined;
    await user.save();

    // Clear cache
    await redisClient.del(`user:${req.user.id}`);

    res.json(formatResponse(true, '2FA disabled successfully'));
  } catch (error) {
    console.error('2FA disable error:', error);
    res.status(500).json(formatResponse(false, 'Error disabling 2FA'));
  }
});

// ==================== INVESTMENT PLAN ROUTES - FULLY INTEGRATED ====================

// Get Investment Plans
app.get('/api/plans', async (req, res) => {
  try {
    const cacheKey = 'investment_plans';
    const cachedPlans = await getCachedResponse(cacheKey);
    
    if (cachedPlans) {
      return res.json(formatResponse(true, 'Plans retrieved successfully', { plans: cachedPlans }));
    }

    const plans = await InvestmentPlan.find({ is_active: true });
    
    // Cache plans for 5 minutes
    await cacheResponse(cacheKey, plans, 300);

    res.json(formatResponse(true, 'Plans retrieved successfully', { plans }));
  } catch (error) {
    console.error('Get plans error:', error);
    res.status(500).json(formatResponse(false, 'Error fetching investment plans'));
  }
});

// ==================== INVESTMENT ROUTES - FULLY INTEGRATED ====================

// Get Investments
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
      .populate('plan', 'name daily_interest total_interest duration raw_material')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit);

    const total = await Investment.countDocuments(query);

    // Calculate stats
    const activeInvestments = await Investment.find({ user: req.user.id, status: 'active' });
    const totalActiveValue = activeInvestments.reduce((sum, inv) => sum + inv.amount, 0);
    const totalEarnings = activeInvestments.reduce((sum, inv) => sum + inv.earned_so_far, 0);

    res.json(formatResponse(true, 'Investments retrieved successfully', {
      investments,
      stats: {
        total_active_value: totalActiveValue,
        total_earnings: totalEarnings,
        active_count: activeInvestments.length
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

// Create Investment - ENHANCED FILE UPLOAD SUPPORT WITH CLOUDINARY
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
    await investment.populate('plan', 'name daily_interest total_interest duration raw_material');

    // Deduct from user balance
    await User.findByIdAndUpdate(req.user.id, { $inc: { balance: -amount } });

    // Clear cache
    await redisClient.del(`user:${req.user.id}`);
    await redisClient.del(`profile:${req.user.id}`);

    // Create transaction record
    await Transaction.create({
      user: req.user.id,
      type: 'investment',
      amount: -amount,
      description: `Investment in ${plan.name} plan`,
      status: 'completed',
      related_investment: investment._id
    });

    // Send real-time balance update
    broadcastToUser(req.user.id, {
      type: 'balance_update',
      balance: user.balance - amount
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

    res.status(201).json(formatResponse(true, 'Investment created successfully! Waiting for admin approval.', { investment }));
  } catch (error) {
    console.error('Create investment error:', error);
    res.status(500).json(formatResponse(false, 'Error creating investment'));
  }
});

// ==================== DEPOSIT ROUTES - FULLY INTEGRATED ====================

// Get Deposits
app.get('/api/deposits', auth, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;

    const deposits = await Deposit.find({ user: req.user.id })
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit);

    const total = await Deposit.countDocuments({ user: req.user.id });

    res.json(formatResponse(true, 'Deposits retrieved successfully', {
      deposits
    }, {
      page,
      limit,
      total,
      pages: Math.ceil(total / limit)
    }));
  } catch (error) {
    console.error('Get deposits error:', error);
    res.status(500).json(formatResponse(false, 'Error fetching deposits'));
  }
});

// Create Deposit - ENHANCED FILE UPLOAD SUPPORT WITH CLOUDINARY
app.post('/api/deposits', auth, upload.single('payment_proof'), [
  body('amount').isFloat({ min: 500 }).withMessage('Minimum deposit is ₦500'),
  body('payment_method').isIn(['bank_transfer', 'crypto', 'paypal', 'card']).withMessage('Invalid payment method'),
  body('transaction_hash').optional().isString(),
  body('bank_name').optional().isString(),
  body('account_name').optional().isString(),
  body('account_number').optional().isString()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json(formatResponse(false, 'Validation failed', { errors: errors.array() }));
    }

    const { amount, payment_method, transaction_hash, bank_name, account_name, account_number } = req.body;
    
    let payment_proof = null;
    if (req.file) {
      payment_proof = await handleFileUpload(req.file, 'deposit-proofs');
    }

    const depositData = {
      user: req.user.id,
      amount: parseFloat(amount),
      payment_method,
      payment_proof,
      transaction_hash: transaction_hash || null
    };

    // Add bank details for bank transfers
    if (payment_method === 'bank_transfer' && bank_name && account_name && account_number) {
      depositData.bank_details = {
        bank_name,
        account_name,
        account_number
      };
    }

    // Add crypto details for crypto payments
    if (payment_method === 'crypto' && transaction_hash) {
      depositData.crypto_details = {
        transaction_hash
      };
    }

    const deposit = new Deposit(depositData);
    await deposit.save();

    // Create notification
    await createNotification(
      req.user.id,
      'Deposit Submitted',
      `Your deposit of ₦${amount.toLocaleString()} has been submitted for approval.`,
      'info',
      '/transaction-history',
      'deposit',
      deposit._id
    );

    res.status(201).json(formatResponse(true, 'Deposit request submitted successfully! Waiting for admin approval.', { deposit }));
  } catch (error) {
    console.error('Create deposit error:', error);
    res.status(500).json(formatResponse(false, 'Error creating deposit request'));
  }
});

// ==================== WITHDRAWAL ROUTES - FULLY INTEGRATED ====================

// Get Withdrawals
app.get('/api/withdrawals', auth, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;

    const withdrawals = await Withdrawal.find({ user: req.user.id })
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit);

    const total = await Withdrawal.countDocuments({ user: req.user.id });

    res.json(formatResponse(true, 'Withdrawals retrieved successfully', {
      withdrawals
    }, {
      page,
      limit,
      total,
      pages: Math.ceil(total / limit)
    }));
  } catch (error) {
    console.error('Get withdrawals error:', error);
    res.status(500).json(formatResponse(false, 'Error fetching withdrawals'));
  }
});

// Create Withdrawal
app.post('/api/withdrawals', auth, [
  body('amount').isFloat({ min: 1000 }).withMessage('Minimum withdrawal is ₦1000'),
  body('payment_method').isIn(['bank_transfer', 'crypto', 'paypal']).withMessage('Invalid payment method'),
  body('bank_name').optional().isString(),
  body('account_name').optional().isString(),
  body('account_number').optional().isString(),
  body('wallet_address').optional().isString(),
  body('paypal_email').optional().isEmail()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json(formatResponse(false, 'Validation failed', { errors: errors.array() }));
    }

    const { amount, payment_method, bank_name, account_name, account_number, wallet_address, paypal_email } = req.body;

    const user = await User.findById(req.user.id);
    if (amount > user.balance) {
      return res.status(400).json(formatResponse(false, 'Insufficient balance for this withdrawal'));
    }

    const withdrawalData = {
      user: req.user.id,
      amount: parseFloat(amount),
      payment_method
    };

    // Add payment details based on method
    if (payment_method === 'bank_transfer') {
      if (!bank_name || !account_name || !account_number) {
        return res.status(400).json(formatResponse(false, 'Bank details are required for bank transfers'));
      }
      withdrawalData.bank_details = {
        bank_name,
        account_name,
        account_number
      };
    } else if (payment_method === 'crypto') {
      if (!wallet_address) {
        return res.status(400).json(formatResponse(false, 'Wallet address is required for crypto withdrawals'));
      }
      withdrawalData.wallet_address = wallet_address;
    } else if (payment_method === 'paypal') {
      if (!paypal_email) {
        return res.status(400).json(formatResponse(false, 'PayPal email is required for PayPal withdrawals'));
      }
      withdrawalData.paypal_email = paypal_email;
    }

    const withdrawal = new Withdrawal(withdrawalData);
    await withdrawal.save();

    // Create notification
    await createNotification(
      req.user.id,
      'Withdrawal Submitted',
      `Your withdrawal request of ₦${amount.toLocaleString()} has been submitted for approval.`,
      'info',
      '/transaction-history',
      'withdrawal',
      withdrawal._id
    );

    res.status(201).json(formatResponse(true, 'Withdrawal request submitted successfully! Waiting for admin approval.', { withdrawal }));
  } catch (error) {
    console.error('Create withdrawal error:', error);
    res.status(500).json(formatResponse(false, 'Error creating withdrawal request'));
  }
});

// ==================== KYC ROUTES - FULLY INTEGRATED ====================

// Submit KYC - ENHANCED FILE UPLOAD SUPPORT WITH CLOUDINARY
app.post('/api/kyc', auth, upload.fields([
  { name: 'id_front', maxCount: 1 },
  { name: 'id_back', maxCount: 1 },
  { name: 'selfie_with_id', maxCount: 1 }
]), [
  body('id_type').isIn(['national_id', 'passport', 'driver_license']).withMessage('Invalid ID type'),
  body('id_number').notEmpty().withMessage('ID number is required')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json(formatResponse(false, 'Validation failed', { errors: errors.array() }));
    }

    const { id_type, id_number } = req.body;
    const files = req.files;

    if (!files || !files.id_front || !files.id_back || !files.selfie_with_id) {
      return res.status(400).json(formatResponse(false, 'All document images are required'));
    }

    // Upload files to Cloudinary
    const id_front = await handleFileUpload(files.id_front[0], 'kyc');
    const id_back = await handleFileUpload(files.id_back[0], 'kyc');
    const selfie_with_id = await handleFileUpload(files.selfie_with_id[0], 'kyc');

    // Check if user already has pending KYC
    const existingKYC = await KYC.findOne({ user: req.user.id, status: 'pending' });
    if (existingKYC) {
      return res.status(400).json(formatResponse(false, 'You already have a pending KYC application'));
    }

    const kyc = new KYC({
      user: req.user.id,
      id_type,
      id_number,
      id_front,
      id_back,
      selfie_with_id
    });

    await kyc.save();

    // Update user KYC status
    await User.findByIdAndUpdate(req.user.id, {
      'kyc_documents.status': 'pending',
      'kyc_documents.submitted_at': new Date()
    });

    // Clear cache
    await redisClient.del(`user:${req.user.id}`);
    await redisClient.del(`profile:${req.user.id}`);

    // Create notification
    await createNotification(
      req.user.id,
      'KYC Submitted',
      'Your KYC application has been submitted and is under review.',
      'info',
      '/profile',
      'kyc',
      kyc._id
    );

    res.status(201).json(formatResponse(true, 'KYC application submitted successfully!', { kyc }));
  } catch (error) {
    console.error('KYC submission error:', error);
    res.status(500).json(formatResponse(false, 'Error submitting KYC application'));
  }
});

// Get KYC Status
app.get('/api/kyc/status', auth, async (req, res) => {
  try {
    const kyc = await KYC.findOne({ user: req.user.id }).sort({ createdAt: -1 });
    
    res.json(formatResponse(true, 'KYC status retrieved', { kyc }));
  } catch (error) {
    console.error('Get KYC status error:', error);
    res.status(500).json(formatResponse(false, 'Error fetching KYC status'));
  }
});

// ==================== REFERRAL ROUTES - FULLY INTEGRATED ====================

// Get Referral Stats
app.get('/api/referrals/stats', auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    
    // Get referral stats
    const totalReferrals = await User.countDocuments({ referred_by: req.user.id });
    const activeReferrals = await User.countDocuments({ 
      referred_by: req.user.id,
      is_active: true 
    });

    // Get referral earnings from transactions
    const referralEarnings = await Transaction.aggregate([
      {
        $match: {
          user: req.user._id,
          type: 'referral',
          status: 'completed'
        }
      },
      {
        $group: {
          _id: null,
          total_earnings: { $sum: '$amount' }
        }
      }
    ]);

    const totalEarnings = referralEarnings.length > 0 ? referralEarnings[0].total_earnings : 0;

    const stats = {
      total_referrals: totalReferrals,
      active_referrals: activeReferrals,
      total_earnings: totalEarnings,
      pending_earnings: 0 // This would be calculated based on pending investments
    };

    res.json(formatResponse(true, 'Referral stats retrieved', { stats }));
  } catch (error) {
    console.error('Get referral stats error:', error);
    res.status(500).json(formatResponse(false, 'Error fetching referral stats'));
  }
});

// ==================== TRANSACTION ROUTES - FULLY INTEGRATED ====================

// Get Transactions
app.get('/api/transactions', auth, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;

    const transactions = await Transaction.find({ user: req.user.id })
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit);

    const total = await Transaction.countDocuments({ user: req.user.id });

    res.json(formatResponse(true, 'Transactions retrieved successfully', {
      transactions
    }, {
      page,
      limit,
      total,
      pages: Math.ceil(total / limit)
    }));
  } catch (error) {
    console.error('Get transactions error:', error);
    res.status(500).json(formatResponse(false, 'Error fetching transactions'));
  }
});

// ==================== SUPPORT ROUTES - FULLY INTEGRATED ====================

// Create Support Ticket
app.post('/api/support/tickets', auth, [
  body('subject').notEmpty().withMessage('Subject is required'),
  body('message').notEmpty().withMessage('Message is required'),
  body('category').isIn(['general', 'technical', 'investment', 'withdrawal', 'kyc', 'other']).withMessage('Invalid category')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json(formatResponse(false, 'Validation failed', { errors: errors.array() }));
    }

    const { subject, message, category } = req.body;

    const ticket = new SupportTicket({
      user: req.user.id,
      subject,
      message,
      category
    });

    await ticket.save();

    // Create notification
    await createNotification(
      req.user.id,
      'Support Ticket Created',
      `Your support ticket "${subject}" has been submitted. We will respond within 24 hours.`,
      'info',
      '/support',
      'support',
      ticket._id
    );

    res.status(201).json(formatResponse(true, 'Support ticket submitted successfully!', { ticket }));
  } catch (error) {
    console.error('Create support ticket error:', error);
    res.status(500).json(formatResponse(false, 'Error creating support ticket'));
  }
});

// Get Support Tickets
app.get('/api/support/tickets', auth, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;

    const tickets = await SupportTicket.find({ user: req.user.id })
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit);

    const total = await SupportTicket.countDocuments({ user: req.user.id });

    res.json(formatResponse(true, 'Support tickets retrieved successfully', {
      tickets
    }, {
      page,
      limit,
      total,
      pages: Math.ceil(total / limit)
    }));
  } catch (error) {
    console.error('Get support tickets error:', error);
    res.status(500).json(formatResponse(false, 'Error fetching support tickets'));
  }
});

// ==================== ADMIN ROUTES - FULLY INTEGRATED ====================

// Admin Dashboard Stats
app.get('/api/admin/dashboard', adminAuth, async (req, res) => {
  try {
    // Get total users
    const totalUsers = await User.countDocuments({ role: 'user' });
    
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
    
    // Get platform earnings (fees)
    const platformEarnings = await Transaction.aggregate([
      { $match: { type: 'fee', status: 'completed' } },
      { $group: { _id: null, total: { $sum: '$amount' } } }
    ]);
    
    // Get active investments count
    const activeInvestments = await Investment.countDocuments({ status: 'active' });

    const stats = {
      total_users: totalUsers,
      total_invested: totalInvested.length > 0 ? totalInvested[0].total : 0,
      total_withdrawn: totalWithdrawn.length > 0 ? totalWithdrawn[0].total : 0,
      pending_approvals: pendingInvestments + pendingDeposits + pendingWithdrawals,
      platform_earnings: platformEarnings.length > 0 ? platformEarnings[0].total : 0,
      active_investments: activeInvestments,
      pending_investments: pendingInvestments,
      pending_deposits: pendingDeposits,
      pending_withdrawals: pendingWithdrawals
    };

    res.json(formatResponse(true, 'Admin dashboard stats retrieved', { stats }));
  } catch (error) {
    console.error('Admin dashboard error:', error);
    res.status(500).json(formatResponse(false, 'Error fetching admin dashboard'));
  }
});

// Admin Users List
app.get('/api/admin/users', adminAuth, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;
    const search = req.query.search;
    const status = req.query.status;

    let query = { role: 'user' };
    
    if (search) {
      query.$or = [
        { full_name: { $regex: search, $options: 'i' } },
        { email: { $regex: search, $options: 'i' } }
      ];
    }
    
    if (status === 'active') {
      query.is_active = true;
    } else if (status === 'inactive') {
      query.is_active = false;
    } else if (status === 'verified') {
      query.kyc_verified = true;
    } else if (status === 'unverified') {
      query.kyc_verified = false;
    }

    const users = await User.find(query)
      .select('full_name email phone balance kyc_verified is_active createdAt')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit);

    const total = await User.countDocuments(query);

    res.json(formatResponse(true, 'Users retrieved successfully', {
      users
    }, {
      page,
      limit,
      total,
      pages: Math.ceil(total / limit)
    }));
  } catch (error) {
    console.error('Admin users error:', error);
    res.status(500).json(formatResponse(false, 'Error fetching users'));
  }
});

// Admin Pending Investments
app.get('/api/admin/pending-investments', adminAuth, async (req, res) => {
  try {
    const investments = await Investment.find({ status: 'pending' })
      .populate('user', 'full_name email')
      .populate('plan', 'name')
      .sort({ createdAt: -1 });

    res.json(formatResponse(true, 'Pending investments retrieved', { investments }));
  } catch (error) {
    console.error('Admin pending investments error:', error);
    res.status(500).json(formatResponse(false, 'Error fetching pending investments'));
  }
});

// Admin Pending Deposits
app.get('/api/admin/pending-deposits', adminAuth, async (req, res) => {
  try {
    const deposits = await Deposit.find({ status: 'pending' })
      .populate('user', 'full_name email')
      .sort({ createdAt: -1 });

    res.json(formatResponse(true, 'Pending deposits retrieved', { deposits }));
  } catch (error) {
    console.error('Admin pending deposits error:', error);
    res.status(500).json(formatResponse(false, 'Error fetching pending deposits'));
  }
});

// Admin Pending Withdrawals
app.get('/api/admin/pending-withdrawals', adminAuth, async (req, res) => {
  try {
    const withdrawals = await Withdrawal.find({ status: 'pending' })
      .populate('user', 'full_name email')
      .sort({ createdAt: -1 });

    res.json(formatResponse(true, 'Pending withdrawals retrieved', { withdrawals }));
  } catch (error) {
    console.error('Admin pending withdrawals error:', error);
    res.status(500).json(formatResponse(false, 'Error fetching pending withdrawals'));
  }
});

// Admin Approve Investment
app.post('/api/admin/approve-investment', adminAuth, [
  body('investment_id').isMongoId().withMessage('Invalid investment ID')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json(formatResponse(false, 'Validation failed', { errors: errors.array() }));
    }

    const { investment_id } = req.body;

    const investment = await Investment.findByIdAndUpdate(
      investment_id,
      { 
        status: 'active',
        approved_by: req.user.id,
        approved_at: new Date()
      },
      { new: true }
    ).populate('user plan');

    if (!investment) {
      return res.status(404).json(formatResponse(false, 'Investment not found'));
    }

    // Create notification for user
    await createNotification(
      investment.user._id,
      'Investment Approved',
      `Your investment of ₦${investment.amount.toLocaleString()} in ${investment.plan.name} has been approved and is now active.`,
      'success',
      '/dashboard',
      'investment',
      investment._id
    );

    res.json(formatResponse(true, 'Investment approved successfully', { investment }));
  } catch (error) {
    console.error('Approve investment error:', error);
    res.status(500).json(formatResponse(false, 'Error approving investment'));
  }
});

// Admin Reject Investment
app.post('/api/admin/reject-investment', adminAuth, [
  body('investment_id').isMongoId().withMessage('Invalid investment ID'),
  body('reason').notEmpty().withMessage('Reason is required')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json(formatResponse(false, 'Validation failed', { errors: errors.array() }));
    }

    const { investment_id, reason } = req.body;

    const investment = await Investment.findById(investment_id).populate('user');
    if (!investment) {
      return res.status(404).json(formatResponse(false, 'Investment not found'));
    }

    // Refund user balance
    await User.findByIdAndUpdate(investment.user._id, {
      $inc: { balance: investment.amount }
    });

    // Update investment status
    investment.status = 'cancelled';
    investment.admin_notes = reason;
    await investment.save();

    // Create transaction record for refund
    await Transaction.create({
      user: investment.user._id,
      type: 'investment',
      amount: investment.amount,
      description: `Investment refund - ${reason}`,
      status: 'completed',
      related_investment: investment._id
    });

    // Clear cache
    await redisClient.del(`user:${investment.user._id}`);

    // Create notification for user
    await createNotification(
      investment.user._id,
      'Investment Rejected',
      `Your investment of ₦${investment.amount.toLocaleString()} has been rejected. Reason: ${reason}. Funds have been refunded to your account.`,
      'error',
      '/investment-history',
      'investment',
      investment._id
    );

    res.json(formatResponse(true, 'Investment rejected and funds refunded', { investment }));
  } catch (error) {
    console.error('Reject investment error:', error);
    res.status(500).json(formatResponse(false, 'Error rejecting investment'));
  }
});

// Admin Approve Deposit
app.post('/api/admin/approve-deposit', adminAuth, [
  body('deposit_id').isMongoId().withMessage('Invalid deposit ID')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json(formatResponse(false, 'Validation failed', { errors: errors.array() }));
    }

    const { deposit_id } = req.body;

    const deposit = await Deposit.findByIdAndUpdate(
      deposit_id,
      { 
        status: 'approved',
        approved_by: req.user.id,
        approved_at: new Date()
      },
      { new: true }
    ).populate('user');

    if (!deposit) {
      return res.status(404).json(formatResponse(false, 'Deposit not found'));
    }

    // Credit user balance (this will be handled by the post hook)

    res.json(formatResponse(true, 'Deposit approved successfully', { deposit }));
  } catch (error) {
    console.error('Approve deposit error:', error);
    res.status(500).json(formatResponse(false, 'Error approving deposit'));
  }
});

// Admin Reject Deposit
app.post('/api/admin/reject-deposit', adminAuth, [
  body('deposit_id').isMongoId().withMessage('Invalid deposit ID'),
  body('reason').notEmpty().withMessage('Reason is required')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json(formatResponse(false, 'Validation failed', { errors: errors.array() }));
    }

    const { deposit_id, reason } = req.body;

    const deposit = await Deposit.findByIdAndUpdate(
      deposit_id,
      { 
        status: 'rejected',
        admin_notes: reason
      },
      { new: true }
    ).populate('user');

    if (!deposit) {
      return res.status(404).json(formatResponse(false, 'Deposit not found'));
    }

    // Create notification for user
    await createNotification(
      deposit.user._id,
      'Deposit Rejected',
      `Your deposit of ₦${deposit.amount.toLocaleString()} has been rejected. Reason: ${reason}`,
      'error',
      '/transaction-history',
      'deposit',
      deposit._id
    );

    res.json(formatResponse(true, 'Deposit rejected successfully', { deposit }));
  } catch (error) {
    console.error('Reject deposit error:', error);
    res.status(500).json(formatResponse(false, 'Error rejecting deposit'));
  }
});

// Admin Approve Withdrawal
app.post('/api/admin/approve-withdrawal', adminAuth, [
  body('withdrawal_id').isMongoId().withMessage('Invalid withdrawal ID')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json(formatResponse(false, 'Validation failed', { errors: errors.array() }));
    }

    const { withdrawal_id } = req.body;

    const withdrawal = await Withdrawal.findByIdAndUpdate(
      withdrawal_id,
      { 
        status: 'approved',
        approved_by: req.user.id,
        approved_at: new Date()
      },
      { new: true }
    ).populate('user');

    if (!withdrawal) {
      return res.status(404).json(formatResponse(false, 'Withdrawal not found'));
    }

    // Deduct user balance (this will be handled by the post hook)

    res.json(formatResponse(true, 'Withdrawal approved successfully', { withdrawal }));
  } catch (error) {
    console.error('Approve withdrawal error:', error);
    res.status(500).json(formatResponse(false, 'Error approving withdrawal'));
  }
});

// Admin Reject Withdrawal
app.post('/api/admin/reject-withdrawal', adminAuth, [
  body('withdrawal_id').isMongoId().withMessage('Invalid withdrawal ID'),
  body('reason').notEmpty().withMessage('Reason is required')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json(formatResponse(false, 'Validation failed', { errors: errors.array() }));
    }

    const { withdrawal_id, reason } = req.body;

    const withdrawal = await Withdrawal.findByIdAndUpdate(
      withdrawal_id,
      { 
        status: 'rejected',
        admin_notes: reason
      },
      { new: true }
    ).populate('user');

    if (!withdrawal) {
      return res.status(404).json(formatResponse(false, 'Withdrawal not found'));
    }

    // Create notification for user
    await createNotification(
      withdrawal.user._id,
      'Withdrawal Rejected',
      `Your withdrawal request of ₦${withdrawal.amount.toLocaleString()} has been rejected. Reason: ${reason}`,
      'error',
      '/transaction-history',
      'withdrawal',
      withdrawal._id
    );

    res.json(formatResponse(true, 'Withdrawal rejected successfully', { withdrawal }));
  } catch (error) {
    console.error('Reject withdrawal error:', error);
    res.status(500).json(formatResponse(false, 'Error rejecting withdrawal'));
  }
});

// Admin KYC Applications
app.get('/api/admin/kyc-applications', adminAuth, async (req, res) => {
  try {
    const status = req.query.status || 'pending';
    
    const applications = await KYC.find({ status })
      .populate('user', 'full_name email phone')
      .populate('reviewed_by', 'full_name')
      .sort({ createdAt: -1 });

    res.json(formatResponse(true, 'KYC applications retrieved', { applications }));
  } catch (error) {
    console.error('Admin KYC applications error:', error);
    res.status(500).json(formatResponse(false, 'Error fetching KYC applications'));
  }
});

// Admin Approve/Reject KYC
app.post('/api/admin/kyc/:id/review', adminAuth, [
  body('status').isIn(['approved', 'rejected']).withMessage('Invalid status'),
  body('notes').optional().isString()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json(formatResponse(false, 'Validation failed', { errors: errors.array() }));
    }

    const { status, notes } = req.body;
    const kycId = req.params.id;

    const kyc = await KYC.findByIdAndUpdate(
      kycId,
      {
        status,
        admin_notes: notes,
        reviewed_by: req.user.id,
        reviewed_at: new Date()
      },
      { new: true }
    ).populate('user');

    if (!kyc) {
      return res.status(404).json(formatResponse(false, 'KYC application not found'));
    }

    // Update user KYC status
    await User.findByIdAndUpdate(kyc.user._id, {
      kyc_verified: status === 'approved',
      'kyc_documents.status': status,
      'kyc_documents.reviewed_at': new Date(),
      'kyc_documents.reviewed_by': req.user.id
    });

    // Clear cache
    await redisClient.del(`user:${kyc.user._id}`);

    // Create notification for user
    const message = status === 'approved' 
      ? 'Your KYC verification has been approved! You now have full access to all platform features.'
      : `Your KYC verification has been rejected. Reason: ${notes}`;

    await createNotification(
      kyc.user._id,
      `KYC ${status === 'approved' ? 'Approved' : 'Rejected'}`,
      message,
      status === 'approved' ? 'success' : 'error',
      '/profile',
      'kyc',
      kyc._id
    );

    res.json(formatResponse(true, `KYC application ${status} successfully`, { kyc }));
  } catch (error) {
    console.error('Review KYC error:', error);
    res.status(500).json(formatResponse(false, 'Error reviewing KYC application'));
  }
});

// ==================== REAL-TIME DATA ROUTES ====================

// WebSocket upgrade handler
const server = app.listen(process.env.PORT || 5000, () => {
  console.log(`Server running on port ${process.env.PORT || 5000}`);
});

server.on('upgrade', (request, socket, head) => {
  wss.handleUpgrade(request, socket, head, (ws) => {
    wss.emit('connection', ws, request);
  });
});

// Real-time balance endpoint
app.get('/api/realtime/balance', auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    res.json(formatResponse(true, 'Balance retrieved', {
      balance: user.balance,
      total_earnings: user.total_earnings
    }));
  } catch (error) {
    console.error('Real-time balance error:', error);
    res.status(500).json(formatResponse(false, 'Error fetching balance'));
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

      await Transaction.create({
        user: investment.user._id,
        type: 'earning',
        amount: dailyEarning,
        description: `Daily earnings from ${investment.plan.name} investment`,
        status: 'completed',
        metadata: { investment_id: investment._id },
        related_investment: investment._id
      });

      // Clear cache
      await redisClient.del(`user:${investment.user._id}`);
      await redisClient.del(`profile:${investment.user._id}`);

      // Send real-time notification
      broadcastToUser(investment.user._id.toString(), {
        type: 'earning_added',
        amount: dailyEarning,
        investment: investment.plan.name,
        balance: (await User.findById(investment.user._id)).balance
      });

      totalEarnings += dailyEarning;
      processedInvestments++;

      // Create notification for large earnings
      if (dailyEarning >= 1000) {
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
      investment.status = 'completed';
      await investment.save();

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
          `Your ${investment.plan.name} investment has been completed successfully.`,
          'success',
          '/dashboard',
          'investment',
          investment._id
        );
      }
    }

    console.log(`✅ Completed ${completedInvestments.length} investment checks`);
  } catch (error) {
    console.error('❌ Error checking completed investments:', error);
  }
});

// ==================== ENHANCED ERROR HANDLING ====================
app.use((err, req, res, next) => {
  console.error('Error Stack:', err.stack);
  
  if (err.name === 'ValidationError') {
    const messages = Object.values(err.errors).map(val => val.message);
    return res.status(400).json(formatResponse(false, 'Validation Error', { errors: messages }));
  }
  
  if (err.code === 11000) {
    const field = Object.keys(err.keyValue)[0];
    return res.status(400).json(formatResponse(false, `${field} already exists`));
  }
  
  if (err.name === 'JsonWebTokenError') {
    return res.status(401).json(formatResponse(false, 'Invalid token'));
  }
  
  if (err.name === 'TokenExpiredError') {
    return res.status(401).json(formatResponse(false, 'Token expired'));
  }

  if (err instanceof multer.MulterError) {
    if (err.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json(formatResponse(false, 'File too large. Maximum size is 10MB.'));
    }
    return res.status(400).json(formatResponse(false, `File upload error: ${err.message}`));
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
    { suggestion: 'Check the API documentation for available endpoints' }
  ));
});

// ==================== GRACEFUL SHUTDOWN ====================
process.on('SIGINT', async () => {
  console.log('🔄 Shutting down gracefully...');
  await mongoose.connection.close();
  await redisClient.quit();
  console.log('✅ MongoDB and Redis connections closed.');
  process.exit(0);
});

process.on('SIGTERM', async () => {
  console.log('🔄 Shutting down gracefully...');
  await mongoose.connection.close();
  await redisClient.quit();
  console.log('✅ MongoDB and Redis connections closed.');
  process.exit(0);
});

// Initialize the application
const initializeApp = async () => {
  try {
    await initializeRedis();
    await connectDB();
    
    console.log(`
🎯 Raw Wealthy Backend v12.0 - ULTIMATE PRODUCTION READY EDITION
🌐 Server running on port ${process.env.PORT || 5000}
🚀 Environment: ${process.env.NODE_ENV || 'development'}
📊 Health Check: http://localhost:${process.env.PORT || 5000}/health
🔗 API Base: http://localhost:${process.env.PORT || 5000}/api
💾 Database: MongoDB Cloud - Raw Wealthy Cluster
☁️  Cloudinary: Configured for file storage
🛡️ Security: Enhanced with Redis, WebSockets, and advanced caching
📧 Email: ${process.env.EMAIL_USER ? 'Configured' : 'Not configured'}
⚡ Real-time: WebSocket support enabled
🎯 Frontend Integration: 100% Connected with real-time updates
🔧 Redis: ${redisClient.isOpen ? 'Connected' : 'Using Fallback'}
    `);
  } catch (error) {
    console.error('❌ Application initialization failed:', error);
    process.exit(1);
  }
};

initializeApp();

module.exports = app;
