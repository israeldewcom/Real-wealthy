// server.js - RAW WEALTHY BACKEND v38.0 - REAL-TIME DASHBOARD EDITION
// COMPLETE REAL-TIME UPDATES: WebSocket Integration + Live Dashboard Updates + Enhanced Performance
// FULLY CONNECTED TO FRONTEND WITH REAL-TIME DATA SYNC

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
import { Server as SocketServer } from 'socket.io';
import http from 'http';
import WebSocket from 'ws';

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

// Add SERVER_URL for absolute image paths
if (!process.env.SERVER_URL) {
  process.env.SERVER_URL = process.env.CLIENT_URL || `http://localhost:${process.env.PORT || 10000}`;
  console.log('✅ Set SERVER_URL:', process.env.SERVER_URL);
}

console.log('============================\n');

// ==================== DYNAMIC CONFIGURATION ====================
const config = {
  // Server
  port: process.env.PORT || 10000,
  nodeEnv: process.env.NODE_ENV || 'production',
  serverURL: process.env.SERVER_URL,
  
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
  },
  
  // Real-time settings
  realTimeUpdateInterval: 30000, // 30 seconds
  cacheTTL: 60000, // 1 minute
  maxConnections: 10000
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

console.log('⚙️  Dynamic Configuration Loaded:');
console.log(`- Port: ${config.port}`);
console.log(`- Environment: ${config.nodeEnv}`);
console.log(`- Client URL: ${config.clientURL}`);
console.log(`- Server URL: ${config.serverURL}`);
console.log(`- Email Enabled: ${config.emailEnabled}`);
console.log(`- Allowed Origins: ${config.allowedOrigins.length}`);
console.log(`- Upload Directory: ${config.uploadDir}`);
console.log(`- Real-time Updates: Every ${config.realTimeUpdateInterval/1000} seconds`);

// ==================== ENHANCED EXPRESS SETUP ====================
const app = express();
const server = http.createServer(app);

// WebSocket Server for real-time updates
const wss = new WebSocket.Server({ server });
const connectedClients = new Map(); // userId -> WebSocket connection

// Socket.IO for advanced real-time features
const io = new SocketServer(server, {
  cors: {
    origin: config.allowedOrigins,
    methods: ["GET", "POST"],
    credentials: true
  },
  transports: ['websocket', 'polling']
});

// Track active user connections
const activeConnections = new Map(); // userId -> socketId

// WebSocket connection handler
wss.on('connection', (ws, req) => {
  console.log('🔌 New WebSocket connection');
  
  ws.on('message', async (message) => {
    try {
      const data = JSON.parse(message);
      
      if (data.type === 'authenticate' && data.token) {
        try {
          const decoded = jwt.verify(data.token, config.jwtSecret);
          const userId = decoded.id;
          
          // Store connection
          connectedClients.set(userId, ws);
          console.log(`✅ WebSocket authenticated for user: ${userId}`);
          
          // Send initial data
          const userData = await getRealTimeUserData(userId);
          ws.send(JSON.stringify({
            type: 'initial_data',
            data: userData
          }));
          
        } catch (error) {
          ws.send(JSON.stringify({
            type: 'error',
            message: 'Authentication failed'
          }));
        }
      }
    } catch (error) {
      console.error('WebSocket message error:', error);
    }
  });
  
  ws.on('close', () => {
    // Remove from connected clients
    for (const [userId, client] of connectedClients.entries()) {
      if (client === ws) {
        connectedClients.delete(userId);
        console.log(`🔌 WebSocket disconnected for user: ${userId}`);
        break;
      }
    }
  });
});

// Socket.IO connection handler
io.on('connection', (socket) => {
  console.log('🔌 New Socket.IO connection:', socket.id);
  
  socket.on('authenticate', async (token) => {
    try {
      const decoded = jwt.verify(token, config.jwtSecret);
      const userId = decoded.id;
      
      // Join user room
      socket.join(`user_${userId}`);
      activeConnections.set(userId, socket.id);
      
      console.log(`✅ Socket.IO authenticated for user: ${userId}`);
      
      // Send welcome message
      socket.emit('authenticated', {
        userId,
        timestamp: new Date().toISOString(),
        message: 'Connected to real-time server'
      });
      
      // Send initial dashboard data
      const dashboardData = await getRealTimeDashboardData(userId);
      socket.emit('dashboard_update', dashboardData);
      
    } catch (error) {
      socket.emit('error', { message: 'Authentication failed' });
    }
  });
  
  socket.on('disconnect', () => {
    // Remove from active connections
    for (const [userId, socketId] of activeConnections.entries()) {
      if (socketId === socket.id) {
        activeConnections.delete(userId);
        console.log(`🔌 Socket.IO disconnected for user: ${userId}`);
        break;
      }
    }
  });
});

// Real-time data helper functions
const broadcastToUser = (userId, event, data) => {
  // Broadcast via Socket.IO
  io.to(`user_${userId}`).emit(event, data);
  
  // Broadcast via WebSocket
  const wsClient = connectedClients.get(userId);
  if (wsClient && wsClient.readyState === WebSocket.OPEN) {
    wsClient.send(JSON.stringify({
      type: event,
      data: data
    }));
  }
};

const broadcastToAdmin = (event, data) => {
  // Broadcast to all admin connections
  io.emit(`admin_${event}`, data);
};

// Security Headers with dynamic CSP
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
  admin: createRateLimiter(15 * 60 * 1000, 500, 'Too many admin requests from this IP'),
  realtime: createRateLimiter(60 * 1000, 60, 'Too many real-time requests, please slow down')
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
app.use('/api/realtime', rateLimiters.realtime);
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

// ==================== DATABASE MODELS - ENHANCED WITH REAL-TIME FIELDS ====================

// Enhanced User Model with real-time fields
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
  // Enhanced fields for real-time dashboard
  total_deposits: { type: Number, default: 0 },
  total_withdrawals: { type: Number, default: 0 },
  total_investments: { type: Number, default: 0 },
  last_deposit_date: Date,
  last_withdrawal_date: Date,
  last_investment_date: Date,
  last_dashboard_update: Date,
  // Real-time tracking
  online_status: { type: Boolean, default: false },
  last_seen: Date,
  connection_id: String
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

// Indexes for real-time queries
userSchema.index({ email: 1 }, { unique: true });
userSchema.index({ referral_code: 1 }, { unique: true, sparse: true });
userSchema.index({ is_active: 1, role: 1, kyc_status: 1 });
userSchema.index({ 'bank_details.last_updated': -1 });
userSchema.index({ createdAt: -1 });
userSchema.index({ last_active: -1 }); // For real-time activity tracking
userSchema.index({ online_status: 1, last_seen: -1 }); // For online users

// Virtual for total portfolio value
userSchema.virtual('portfolio_value').get(function() {
  return this.balance + this.total_earnings + this.referral_earnings;
});

// Virtual for real-time daily interest calculation
userSchema.virtual('estimated_daily_interest').get(function() {
  // This will be calculated dynamically based on active investments
  return 0;
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

// Real-time update method
userSchema.methods.updateRealTimeStatus = async function(isOnline = false, connectionId = null) {
  this.online_status = isOnline;
  this.last_seen = new Date();
  if (connectionId) this.connection_id = connectionId;
  await this.save();
  
  // Broadcast status update to admin
  if (this.role === 'user') {
    broadcastToAdmin('user_status_update', {
      userId: this._id,
      online: isOnline,
      lastSeen: this.last_seen
    });
  }
};

const User = mongoose.model('User', userSchema);

// Investment Plan Model - Enhanced for real-time updates
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
  // Real-time performance metrics
  performance_24h: { type: Number, default: 0 },
  performance_7d: { type: Number, default: 0 },
  performance_30d: { type: Number, default: 0 },
  trending_score: { type: Number, default: 0 },
  last_updated: Date,
  metadata: { type: mongoose.Schema.Types.Mixed, default: {} }
}, { 
  timestamps: true 
});

investmentPlanSchema.index({ is_active: 1, is_popular: 1, category: 1 });
investmentPlanSchema.index({ min_amount: 1 });
investmentPlanSchema.index({ trending_score: -1 }); // For trending plans
investmentPlanSchema.index({ last_updated: -1 }); // For real-time updates

const InvestmentPlan = mongoose.model('InvestmentPlan', investmentPlanSchema);

// Investment Model - Enhanced with real-time tracking
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
  // Enhanced fields for real-time updates
  admin_notes: String,
  proof_verified_by: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  proof_verified_at: Date,
  investment_image_url: String,
  // Real-time progress tracking
  progress_percentage: { type: Number, default: 0, min: 0, max: 100 },
  remaining_days: Number,
  next_earning_date: Date,
  last_updated: Date
}, { 
  timestamps: true 
});

investmentSchema.index({ user: 1, status: 1 });
investmentSchema.index({ end_date: 1 });
investmentSchema.index({ createdAt: -1 });
investmentSchema.index({ last_updated: -1 }); // For real-time updates
investmentSchema.index({ status: 1, next_earning_date: 1 }); // For earning calculations

// Pre-save hook to update real-time fields
investmentSchema.pre('save', function(next) {
  this.last_updated = new Date();
  
  // Calculate progress percentage
  if (this.start_date && this.end_date) {
    const totalDuration = this.end_date - this.start_date;
    const elapsedDuration = Date.now() - this.start_date;
    this.progress_percentage = Math.min(100, Math.max(0, (elapsedDuration / totalDuration) * 100));
    
    // Calculate remaining days
    this.remaining_days = Math.max(0, Math.ceil((this.end_date - Date.now()) / (1000 * 60 * 60 * 24)));
  }
  
  // Set next earning date (tomorrow at midnight)
  if (this.status === 'active') {
    const tomorrow = new Date();
    tomorrow.setDate(tomorrow.getDate() + 1);
    tomorrow.setHours(0, 0, 0, 0);
    this.next_earning_date = tomorrow;
  }
  
  next();
});

const Investment = mongoose.model('Investment', investmentSchema);

// Deposit Model - Enhanced for real-time updates
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
  // Enhanced fields for real-time
  deposit_image_url: String,
  proof_verified_by: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  proof_verified_at: Date,
  // Real-time tracking
  processing_stage: { type: String, enum: ['submitted', 'under_review', 'processing', 'completed'], default: 'submitted' },
  estimated_completion: Date,
  last_status_update: Date
}, { 
  timestamps: true 
});

depositSchema.index({ user: 1, status: 1 });
depositSchema.index({ reference: 1 }, { unique: true, sparse: true });
depositSchema.index({ createdAt: -1 });
depositSchema.index({ last_status_update: -1 }); // For real-time updates

const Deposit = mongoose.model('Deposit', depositSchema);

// Withdrawal Model - Enhanced for real-time updates
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
  // Enhanced fields for real-time
  payment_proof_url: String,
  proof_verified_by: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  proof_verified_at: Date,
  // Real-time tracking
  processing_stage: { type: String, enum: ['submitted', 'under_review', 'processing', 'sent', 'completed'], default: 'submitted' },
  estimated_completion: Date,
  last_status_update: Date
}, { 
  timestamps: true 
});

withdrawalSchema.index({ user: 1, status: 1 });
withdrawalSchema.index({ reference: 1 }, { unique: true, sparse: true });
withdrawalSchema.index({ createdAt: -1 });
withdrawalSchema.index({ last_status_update: -1 }); // For real-time updates

const Withdrawal = mongoose.model('Withdrawal', withdrawalSchema);

// Transaction Model - Enhanced for real-time history
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
  // Enhanced fields for real-time
  payment_proof_url: String,
  admin_notes: String,
  // Real-time notification
  notified: { type: Boolean, default: false },
  notification_sent_at: Date
}, { 
  timestamps: true 
});

transactionSchema.index({ user: 1, createdAt: -1 });
transactionSchema.index({ type: 1, status: 1 });
transactionSchema.index({ reference: 1 });
transactionSchema.index({ createdAt: -1, notified: 1 }); // For real-time notifications

const Transaction = mongoose.model('Transaction', transactionSchema);

// KYC Submission Model - Enhanced for real-time
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
  metadata: { type: mongoose.Schema.Types.Mixed, default: {} },
  // Real-time tracking
  review_progress: { type: Number, default: 0, min: 0, max: 100 },
  last_review_update: Date
}, { 
  timestamps: true 
});

kycSubmissionSchema.index({ status: 1, submitted_at: -1 });
kycSubmissionSchema.index({ last_review_update: -1 }); // For real-time updates

const KYCSubmission = mongoose.model('KYCSubmission', kycSubmissionSchema);

// Support Ticket Model - Enhanced for real-time
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
  metadata: { type: mongoose.Schema.Types.Mixed, default: {} },
  // Real-time chat
  messages: [{
    sender: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    message: String,
    attachments: [{
      filename: String,
      url: String,
      size: Number,
      mime_type: String
    }],
    read_by: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    sent_at: { type: Date, default: Date.now }
  }],
  last_activity: Date
}, { 
  timestamps: true 
});

supportTicketSchema.index({ user: 1, status: 1, createdAt: -1 });
supportTicketSchema.index({ last_activity: -1 }); // For real-time updates

const SupportTicket = mongoose.model('SupportTicket', supportTicketSchema);

// Referral Model - Enhanced for real-time
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
  // Real-time tracking
  last_activity: Date,
  total_earned_from_user: { type: Number, default: 0 }
}, { 
  timestamps: true 
});

referralSchema.index({ referrer: 1, status: 1 });
referralSchema.index({ last_activity: -1 }); // For real-time updates

const Referral = mongoose.model('Referral', referralSchema);

// Notification Model - Enhanced for real-time
const notificationSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  title: { type: String, required: true },
  message: { type: String, required: true },
  type: { type: String, enum: ['info', 'success', 'warning', 'error', 'promotional', 'investment', 'withdrawal', 'deposit', 'kyc', 'referral', 'system'], default: 'info' },
  is_read: { type: Boolean, default: false },
  is_email_sent: { type: Boolean, default: false },
  action_url: String,
  priority: { type: Number, default: 0, min: 0, max: 3 },
  metadata: { type: mongoose.Schema.Types.Mixed, default: {} },
  // Real-time fields
  delivered_via_socket: { type: Boolean, default: false },
  socket_delivered_at: Date,
  expires_at: Date
}, { 
  timestamps: true 
});

notificationSchema.index({ user: 1, is_read: 1, createdAt: -1 });
notificationSchema.index({ expires_at: 1 }, { expireAfterSeconds: 2592000 }); // Auto-delete after 30 days
notificationSchema.index({ delivered_via_socket: 1 }); // For real-time delivery tracking

const Notification = mongoose.model('Notification', notificationSchema);

// Admin Audit Log Model with real-time
const adminAuditSchema = new mongoose.Schema({
  admin_id: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  action: { type: String, required: true },
  target_type: { type: String, enum: ['user', 'investment', 'deposit', 'withdrawal', 'kyc', 'transaction', 'plan', 'system'] },
  target_id: mongoose.Schema.Types.ObjectId,
  details: mongoose.Schema.Types.Mixed,
  ip_address: String,
  user_agent: String,
  metadata: { type: mongoose.Schema.Types.Mixed, default: {} },
  // Real-time broadcast
  broadcast_to_admins: { type: Boolean, default: false },
  broadcasted_at: Date
}, { 
  timestamps: true 
});

adminAuditSchema.index({ admin_id: 1, createdAt: -1 });
adminAuditSchema.index({ broadcast_to_admins: 1, createdAt: -1 }); // For real-time broadcasting

const AdminAudit = mongoose.model('AdminAudit', adminAuditSchema);

// Real-time Dashboard Cache Model
const dashboardCacheSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, unique: true },
  data: { type: mongoose.Schema.Types.Mixed, required: true },
  expires_at: { type: Date, required: true },
  last_updated: { type: Date, default: Date.now }
}, {
  timestamps: true
});

dashboardCacheSchema.index({ expires_at: 1 }, { expireAfterSeconds: 0 }); // Auto-delete expired
dashboardCacheSchema.index({ user: 1, last_updated: -1 });

const DashboardCache = mongoose.model('DashboardCache', dashboardCacheSchema);

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

// Real-time dashboard data function
const getRealTimeUserData = async (userId) => {
  try {
    // Check cache first
    const cached = await DashboardCache.findOne({ 
      user: userId,
      expires_at: { $gt: new Date() }
    });
    
    if (cached) {
      return cached.data;
    }
    
    // Get fresh data
    const [user, investments, transactions, notifications, kyc, deposits, withdrawals, referrals] = await Promise.all([
      User.findById(userId).lean(),
      Investment.find({ user: userId })
        .populate('plan', 'name daily_interest duration total_interest')
        .sort({ createdAt: -1 })
        .limit(10)
        .lean(),
      Transaction.find({ user: userId })
        .sort({ createdAt: -1 })
        .limit(20)
        .lean(),
      Notification.find({ user: userId, is_read: false })
        .sort({ createdAt: -1 })
        .limit(10)
        .lean(),
      KYCSubmission.findOne({ user: userId }).lean(),
      Deposit.find({ user: userId })
        .sort({ createdAt: -1 })
        .limit(10)
        .lean(),
      Withdrawal.find({ user: userId })
        .sort({ createdAt: -1 })
        .limit(10)
        .lean(),
      Referral.find({ referrer: userId })
        .populate('referred_user', 'full_name email createdAt balance')
        .sort({ createdAt: -1 })
        .limit(5)
        .lean()
    ]);

    if (!user) return null;

    // Calculate real-time stats
    const activeInvestments = investments.filter(inv => inv.status === 'active');
    const totalActiveValue = activeInvestments.reduce((sum, inv) => sum + inv.amount, 0);
    
    // Calculate daily interest in real-time
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

    // Calculate hourly earnings
    const hourlyEarnings = dailyInterest / 24;
    const minuteEarnings = hourlyEarnings / 60;
    
    // Calculate time since last update
    const now = new Date();
    const lastUpdate = user.last_dashboard_update || user.updatedAt;
    const timeSinceUpdate = now - new Date(lastUpdate);
    const hoursSinceUpdate = timeSinceUpdate / (1000 * 60 * 60);
    
    // Calculate earned since last update
    const earnedSinceUpdate = hourlyEarnings * hoursSinceUpdate;

    const realTimeData = {
      user: {
        ...user,
        online_status: activeConnections.has(userId.toString()),
        last_seen: user.last_seen || user.last_active
      },
      
      // Real-time financial metrics
      financial_summary: {
        current_balance: user.balance || 0,
        total_earnings: totalEarnings,
        referral_earnings: referralEarnings,
        daily_interest: dailyInterest,
        hourly_earnings: hourlyEarnings,
        minute_earnings: minuteEarnings,
        earned_since_last_update: earnedSinceUpdate,
        active_investment_value: totalActiveValue,
        portfolio_value: (user.balance || 0) + totalEarnings + referralEarnings,
        total_deposits: totalDepositsAmount,
        total_withdrawals: totalWithdrawalsAmount,
        net_profit: totalEarnings + referralEarnings - totalWithdrawalsAmount
      },
      
      // Real-time counts
      counts: {
        total_investments: investments.length,
        active_investments: activeInvestments.length,
        pending_investments: investments.filter(inv => inv.status === 'pending').length,
        total_deposits: deposits.filter(d => d.status === 'approved').length,
        total_withdrawals: withdrawals.filter(w => w.status === 'paid').length,
        referral_count: user.referral_count || 0,
        unread_notifications: notifications.length
      },
      
      // Recent activity
      recent_activity: {
        investments: investments.slice(0, 5),
        transactions: transactions.slice(0, 10),
        deposits: deposits.slice(0, 5),
        withdrawals: withdrawals.slice(0, 5),
        referrals: referrals.slice(0, 5)
      },
      
      // Real-time investment progress
      investment_progress: activeInvestments.map(inv => {
        const remainingDays = Math.max(0, Math.ceil((new Date(inv.end_date) - now) / (1000 * 60 * 60 * 24)));
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
          expected_total: inv.expected_earnings || 0
        };
      }),
      
      // Status indicators
      status: {
        kyc_status: user.kyc_status || 'not_submitted',
        kyc_verified: user.kyc_verified || false,
        account_active: user.is_active || false,
        email_verified: user.is_verified || false,
        bank_verified: user.bank_details?.verified || false
      },
      
      // Timestamps
      timestamps: {
        last_update: now.toISOString(),
        next_earning_update: new Date(now.getTime() + 3600000).toISOString(), // 1 hour from now
        server_time: now.toISOString()
      }
    };

    // Cache the data
    const expiresAt = new Date(now.getTime() + config.cacheTTL);
    await DashboardCache.findOneAndUpdate(
      { user: userId },
      { 
        data: realTimeData,
        expires_at: expiresAt,
        last_updated: now
      },
      { upsert: true, new: true }
    );

    // Update user's last dashboard update time
    await User.findByIdAndUpdate(userId, { 
      last_dashboard_update: now 
    });

    return realTimeData;
  } catch (error) {
    console.error('Error getting real-time user data:', error);
    return null;
  }
};

// Enhanced createNotification with real-time delivery
const createNotification = async (userId, title, message, type = 'info', actionUrl = null, metadata = {}, realTime = true) => {
  try {
    const notification = new Notification({
      user: userId,
      title,
      message,
      type,
      action_url: actionUrl,
      metadata: {
        ...metadata,
        sentAt: new Date(),
        realTimeDelivered: false
      },
      expires_at: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000) // 30 days
    });
    
    await notification.save();
    
    // Real-time delivery via WebSocket/Socket.IO
    if (realTime) {
      const notificationData = {
        _id: notification._id,
        title,
        message,
        type,
        action_url: actionUrl,
        createdAt: notification.createdAt,
        metadata: notification.metadata
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
      
      // Mark as delivered
      notification.delivered_via_socket = true;
      notification.socket_delivered_at = new Date();
      await notification.save();
    }
    
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
      notification.is_email_sent = true;
      await notification.save();
    }
    
    return notification;
  } catch (error) {
    console.error('Error creating notification:', error);
    return null;
  }
};

// Enhanced createTransaction with real-time updates
const createTransaction = async (userId, type, amount, description, status = 'completed', metadata = {}, proofUrl = null, realTime = true) => {
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
      metadata: {
        ...metadata,
        processedAt: new Date(),
        realTimeBroadcast: realTime
      }
    });
    
    await transaction.save();
    
    // Update user balance in real-time
    user.balance = balanceAfter;
    
    // Update user statistics based on transaction type
    if (type === 'deposit' && status === 'completed') {
      user.total_deposits = (user.total_deposits || 0) + Math.abs(amount);
      user.last_deposit_date = new Date();
    } else if (type === 'withdrawal' && status === 'completed') {
      user.total_withdrawals = (user.total_withdrawals || 0) + Math.abs(amount);
      user.last_withdrawal_date = new Date();
    } else if (type === 'investment' && status === 'completed') {
      user.total_investments = (user.total_investments || 0) + Math.abs(amount);
      user.last_investment_date = new Date();
    } else if (type === 'earning') {
      user.total_earnings = (user.total_earnings || 0) + Math.abs(amount);
    } else if (type === 'referral') {
      user.referral_earnings = (user.referral_earnings || 0) + Math.abs(amount);
    }
    
    await user.save();
    
    // Clear dashboard cache for real-time update
    await DashboardCache.findOneAndDelete({ user: userId });
    
    // Real-time broadcast
    if (realTime) {
      const transactionData = {
        _id: transaction._id,
        type,
        amount,
        description,
        status,
        balance_before: balanceBefore,
        balance_after: balanceAfter,
        createdAt: transaction.createdAt,
        reference: transaction.reference
      };
      
      // Broadcast to user
      broadcastToUser(userId, 'transaction_update', transactionData);
      
      // Broadcast to admin if large transaction
      if (Math.abs(amount) >= 100000) { // Large transaction threshold
        broadcastToAdmin('large_transaction', {
          userId,
          userName: user.full_name,
          transaction: transactionData
        });
      }
    }
    
    return transaction;
  } catch (error) {
    console.error('Error creating transaction:', error);
    return null;
  }
};

// Real-time dashboard data function
const getRealTimeDashboardData = async (userId) => {
  try {
    const realTimeData = await getRealTimeUserData(userId);
    
    if (!realTimeData) {
      throw new Error('Could not fetch real-time data');
    }
    
    // Add real-time market data (simulated)
    const marketData = {
      btc_price: 45000 + Math.random() * 1000,
      gold_price: 1950 + Math.random() * 50,
      oil_price: 75 + Math.random() * 5,
      market_trend: Math.random() > 0.5 ? 'up' : 'down',
      last_updated: new Date().toISOString()
    };
    
    // Add trending investments
    const trendingPlans = await InvestmentPlan.find({ is_active: true })
      .sort({ trending_score: -1 })
      .limit(3)
      .lean();
    
    const enhancedData = {
      ...realTimeData,
      market_data: marketData,
      trending_plans: trendingPlans,
      server_status: {
        connected: true,
        latency: Math.floor(Math.random() * 100), // Simulated latency
        uptime: process.uptime(),
        timestamp: new Date().toISOString()
      }
    };
    
    return enhancedData;
  } catch (error) {
    console.error('Error getting real-time dashboard data:', error);
    return null;
  }
};

// Real-time admin dashboard function
const getRealTimeAdminDashboard = async () => {
  try {
    const now = new Date();
    const today = new Date(now.setHours(0, 0, 0, 0));
    const yesterday = new Date(today.getTime() - 24 * 60 * 60 * 1000);
    const lastWeek = new Date(today.getTime() - 7 * 24 * 60 * 60 * 1000);
    
    const [
      totalUsers,
      activeUsersToday,
      onlineUsers,
      totalInvestments,
      activeInvestments,
      totalDeposits,
      totalWithdrawals,
      pendingDeposits,
      pendingWithdrawals,
      pendingKYC,
      recentTransactions,
      platformEarnings,
      userGrowth
    ] = await Promise.all([
      User.countDocuments({}),
      User.countDocuments({ last_login: { $gte: today } }),
      User.countDocuments({ online_status: true }),
      Investment.countDocuments({}),
      Investment.countDocuments({ status: 'active' }),
      Deposit.countDocuments({ status: 'approved' }),
      Withdrawal.countDocuments({ status: 'paid' }),
      Deposit.countDocuments({ status: 'pending' }),
      Withdrawal.countDocuments({ status: 'pending' }),
      KYCSubmission.countDocuments({ status: 'pending' }),
      Transaction.find({})
        .populate('user', 'full_name email')
        .sort({ createdAt: -1 })
        .limit(20)
        .lean(),
      Transaction.aggregate([
        { $match: { type: 'fee', status: 'completed' } },
        { $group: { _id: null, total: { $sum: '$amount' } } }
      ]),
      User.aggregate([
        {
          $group: {
            _id: {
              year: { $year: '$createdAt' },
              month: { $month: '$createdAt' },
              day: { $dayOfMonth: '$createdAt' }
            },
            count: { $sum: 1 }
          }
        },
        { $sort: { '_id.year': -1, '_id.month': -1, '_id.day': -1 } },
        { $limit: 30 }
      ])
    ]);
    
    // Calculate real-time metrics
    const totalDepositsAmount = await Deposit.aggregate([
      { $match: { status: 'approved' } },
      { $group: { _id: null, total: { $sum: '$amount' } } }
    ]);
    
    const totalWithdrawalsAmount = await Withdrawal.aggregate([
      { $match: { status: 'paid' } },
      { $group: { _id: null, total: { $sum: '$amount' } } }
    ]);
    
    const activeInvestmentsValue = await Investment.aggregate([
      { $match: { status: 'active' } },
      { $group: { _id: null, total: { $sum: '$amount' } } }
    ]);
    
    const adminDashboard = {
      overview: {
        total_users: totalUsers,
        active_users_today: activeUsersToday,
        online_users: onlineUsers,
        total_investments: totalInvestments,
        active_investments: activeInvestments,
        total_deposits: totalDeposits,
        total_withdrawals: totalWithdrawals,
        pending_deposits: pendingDeposits,
        pending_withdrawals: pendingWithdrawals,
        pending_kyc: pendingKYC
      },
      
      financial: {
        total_deposits_amount: totalDepositsAmount[0]?.total || 0,
        total_withdrawals_amount: totalWithdrawalsAmount[0]?.total || 0,
        active_investments_value: activeInvestmentsValue[0]?.total || 0,
        platform_earnings: platformEarnings[0]?.total || 0,
        net_cash_flow: (totalDepositsAmount[0]?.total || 0) - (totalWithdrawalsAmount[0]?.total || 0)
      },
      
      real_time: {
        server_time: new Date().toISOString(),
        uptime: process.uptime(),
        memory_usage: {
          rss: `${Math.round(process.memoryUsage().rss / 1024 / 1024)}MB`,
          heapTotal: `${Math.round(process.memoryUsage().heapTotal / 1024 / 1024)}MB`,
          heapUsed: `${Math.round(process.memoryUsage().heapUsed / 1024 / 1024)}MB`
        },
        connections: {
          websocket: connectedClients.size,
          socketio: activeConnections.size,
          total: connectedClients.size + activeConnections.size
        }
      },
      
      recent_activity: {
        transactions: recentTransactions.slice(0, 10),
        user_growth: userGrowth,
        last_updated: new Date().toISOString()
      },
      
      alerts: {
        critical: pendingDeposits > 10 ? 'High number of pending deposits' : null,
        warning: pendingWithdrawals > 5 ? 'Pending withdrawals need attention' : null,
        info: pendingKYC > 0 ? `${pendingKYC} KYC submissions pending` : null
      }
    };
    
    return adminDashboard;
  } catch (error) {
    console.error('Error getting real-time admin dashboard:', error);
    return null;
  }
};

// Admin audit log function with real-time broadcast
const createAdminAudit = async (adminId, action, targetType, targetId, details = {}, ip = '', userAgent = '', broadcast = false) => {
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
        timestamp: new Date(),
        broadcasted: broadcast
      },
      broadcast_to_admins: broadcast
    });
    
    await audit.save();
    
    // Broadcast to other admins in real-time
    if (broadcast) {
      const admin = await User.findById(adminId);
      const auditData = {
        ...audit.toObject(),
        admin_name: admin?.full_name || 'Unknown Admin'
      };
      
      broadcastToAdmin('audit_log', auditData);
      audit.broadcasted_at = new Date();
      await audit.save();
    }
    
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
    
    // Update last active timestamp
    user.last_active = new Date();
    await user.save();
    
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
// ==================== REAL-TIME ENDPOINTS ====================

// Real-time dashboard endpoint
app.get('/api/realtime/dashboard', auth, async (req, res) => {
  try {
    const userId = req.user._id;
    const data = await getRealTimeDashboardData(userId);
    
    if (!data) {
      return res.status(500).json(formatResponse(false, 'Failed to load real-time dashboard'));
    }
    
    res.json(formatResponse(true, 'Real-time dashboard data loaded', data));
  } catch (error) {
    handleError(res, error, 'Error loading real-time dashboard');
  }
});

// WebSocket authentication endpoint
app.post('/api/realtime/auth', auth, async (req, res) => {
  try {
    const userId = req.user._id;
    const token = req.user.generateAuthToken();
    
    // Update user online status
    await User.findByIdAndUpdate(userId, {
      online_status: true,
      last_seen: new Date()
    });
    
    res.json(formatResponse(true, 'Real-time authentication successful', {
      token,
      websocket_url: `${config.serverURL.replace('http', 'ws')}`,
      socketio_url: `${config.serverURL}`,
      user_id: userId,
      expires_in: config.jwtExpiresIn
    }));
  } catch (error) {
    handleError(res, error, 'Real-time authentication failed');
  }
});

// Real-time notifications endpoint
app.get('/api/realtime/notifications', auth, async (req, res) => {
  try {
    const userId = req.user._id;
    const { unread = 'true', limit = 20 } = req.query;
    
    const query = { user: userId };
    if (unread === 'true') {
      query.is_read = false;
    }
    
    const notifications = await Notification.find(query)
      .sort({ createdAt: -1 })
      .limit(parseInt(limit))
      .lean();
    
    // Mark as delivered via API
    if (unread === 'true') {
      await Notification.updateMany(
        { user: userId, is_read: false },
        { delivered_via_socket: true, socket_delivered_at: new Date() }
      );
    }
    
    res.json(formatResponse(true, 'Real-time notifications loaded', { notifications }));
  } catch (error) {
    handleError(res, error, 'Error loading real-time notifications');
  }
});

// Real-time market data endpoint
app.get('/api/realtime/market', async (req, res) => {
  try {
    // Simulated market data (in production, connect to real API)
    const marketData = {
      timestamp: new Date().toISOString(),
      commodities: {
        gold: {
          price: 1950.25 + Math.random() * 10,
          change: Math.random() > 0.5 ? '+' + (Math.random() * 5).toFixed(2) : '-' + (Math.random() * 5).toFixed(2),
          change_percent: Math.random() > 0.5 ? '+' + (Math.random() * 2).toFixed(2) + '%' : '-' + (Math.random() * 2).toFixed(2) + '%'
        },
        oil: {
          price: 75.80 + Math.random() * 2,
          change: Math.random() > 0.5 ? '+' + (Math.random() * 1).toFixed(2) : '-' + (Math.random() * 1).toFixed(2),
          change_percent: Math.random() > 0.5 ? '+' + (Math.random() * 1.5).toFixed(2) + '%' : '-' + (Math.random() * 1.5).toFixed(2) + '%'
        },
        cocoa: {
          price: 3500 + Math.random() * 100,
          change: Math.random() > 0.5 ? '+' + (Math.random() * 50).toFixed(2) : '-' + (Math.random() * 50).toFixed(2),
          change_percent: Math.random() > 0.5 ? '+' + (Math.random() * 3).toFixed(2) + '%' : '-' + (Math.random() * 3).toFixed(2) + '%'
        }
      },
      crypto: {
        bitcoin: {
          price: 45000 + Math.random() * 1000,
          change: Math.random() > 0.5 ? '+' + (Math.random() * 500).toFixed(2) : '-' + (Math.random() * 500).toFixed(2),
          change_percent: Math.random() > 0.5 ? '+' + (Math.random() * 5).toFixed(2) + '%' : '-' + (Math.random() * 5).toFixed(2) + '%'
        },
        ethereum: {
          price: 2500 + Math.random() * 200,
          change: Math.random() > 0.5 ? '+' + (Math.random() * 100).toFixed(2) : '-' + (Math.random() * 100).toFixed(2),
          change_percent: Math.random() > 0.5 ? '+' + (Math.random() * 4).toFixed(2) + '%' : '-' + (Math.random() * 4).toFixed(2) + '%'
        }
      },
      indices: {
        nasdaq: {
          value: 14500 + Math.random() * 100,
          change: Math.random() > 0.5 ? '+' + (Math.random() * 50).toFixed(2) : '-' + (Math.random() * 50).toFixed(2)
        },
        sp500: {
          value: 4500 + Math.random() * 50,
          change: Math.random() > 0.5 ? '+' + (Math.random() * 25).toFixed(2) : '-' + (Math.random() * 25).toFixed(2)
        }
      }
    };
    
    res.json(formatResponse(true, 'Real-time market data', marketData));
  } catch (error) {
    handleError(res, error, 'Error loading market data');
  }
});

// Real-time user activity endpoint
app.get('/api/realtime/activity', auth, async (req, res) => {
  try {
    const userId = req.user._id;
    
    const [recentTransactions, recentInvestments, recentNotifications] = await Promise.all([
      Transaction.find({ user: userId })
        .sort({ createdAt: -1 })
        .limit(10)
        .lean(),
      Investment.find({ user: userId })
        .populate('plan', 'name')
        .sort({ createdAt: -1 })
        .limit(5)
        .lean(),
      Notification.find({ user: userId })
        .sort({ createdAt: -1 })
        .limit(5)
        .lean()
    ]);
    
    const activity = {
      transactions: recentTransactions.map(t => ({
        ...t,
        time_ago: getTimeAgo(t.createdAt),
        icon: getTransactionIcon(t.type)
      })),
      investments: recentInvestments.map(i => ({
        ...i,
        time_ago: getTimeAgo(i.createdAt),
        status_color: getStatusColor(i.status)
      })),
      notifications: recentNotifications.map(n => ({
        ...n,
        time_ago: getTimeAgo(n.createdAt),
        type_color: getNotificationColor(n.type)
      })),
      last_updated: new Date().toISOString()
    };
    
    res.json(formatResponse(true, 'Real-time activity loaded', activity));
  } catch (error) {
    handleError(res, error, 'Error loading real-time activity');
  }
});

// Helper functions for real-time display
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

function getTransactionIcon(type) {
  const icons = {
    'deposit': '💰',
    'withdrawal': '💳',
    'investment': '📈',
    'earning': '💹',
    'referral': '👥',
    'bonus': '🎁',
    'fee': '📉',
    'refund': '↩️',
    'transfer': '🔄'
  };
  return icons[type] || '📊';
}

function getStatusColor(status) {
  const colors = {
    'pending': 'warning',
    'active': 'success',
    'completed': 'info',
    'cancelled': 'error',
    'failed': 'error'
  };
  return colors[status] || 'default';
}

function getNotificationColor(type) {
  const colors = {
    'info': 'blue',
    'success': 'green',
    'warning': 'yellow',
    'error': 'red',
    'investment': 'purple',
    'promotional': 'pink'
  };
  return colors[type] || 'gray';
}



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
      maxPoolSize: 50, // Increased for real-time connections
      retryWrites: true
    });
    
    console.log('✅ MongoDB connected successfully');
    
    // Load investment plans into config
    await loadInvestmentPlans();
    
    // Create admin user if it doesn't exist
    await createAdminUser();
    
    // Create indexes if they don't exist
    await createDatabaseIndexes();
    
    // Initialize real-time data
    await initializeRealTimeData();
    
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
      display_order: 1,
      performance_24h: 0.5,
      performance_7d: 3.2,
      performance_30d: 9.8,
      trending_score: 85
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
      display_order: 2,
      performance_24h: 0.8,
      performance_7d: 4.5,
      performance_30d: 12.3,
      trending_score: 92
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
      display_order: 3,
      performance_24h: 1.2,
      performance_7d: 6.7,
      performance_30d: 18.5,
      trending_score: 78
    }
  ];

  try {
    await InvestmentPlan.insertMany(defaultPlans);
    config.investmentPlans = defaultPlans;
    console.log('✅ Created default investment plans with real-time metrics');
  } catch (error) {
    console.error('Error creating default investment plans:', error);
  }
};

const createAdminUser = async () => {
  try {
    console.log('🚀 ADMIN SETUP STARTING...');
    
    const adminEmail = process.env.ADMIN_EMAIL || 'admin@rawwealthy.com';
    const adminPassword = process.env.ADMIN_PASSWORD || 'Admin123456';
    
    console.log(`🔑 Using: ${adminEmail} / ${adminPassword}`);
    
    // Check if admin already exists
    const existingAdmin = await User.findOne({ email: adminEmail });
    if (existingAdmin) {
      console.log('✅ Admin already exists');
      
      // Update admin password if it's the default
      if (adminPassword === 'Admin123456') {
        const salt = await bcrypt.genSalt(12);
        const hash = await bcrypt.hash(adminPassword, salt);
        existingAdmin.password = hash;
        await existingAdmin.save();
        console.log('✅ Admin password updated');
      }
      
      return;
    }
    
    // Create admin user
    const salt = await bcrypt.genSalt(12);
    const hash = await bcrypt.hash(adminPassword, salt);
    
    const adminData = {
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
      sms_notifications: false
    };
    
    const admin = new User(adminData);
    await admin.save();
    
    console.log('🎉 ADMIN CREATED SUCCESSFULLY!');
    console.log(`📧 Email: ${adminEmail}`);
    console.log(`🔑 Password: ${adminPassword}`);
    console.log('👉 Login at: /api/auth/login');
    console.log('🚀 ADMIN SETUP COMPLETE');
    
  } catch (error) {
    console.error('❌ ADMIN SETUP ERROR:', error.message);
    console.error(error.stack);
  }
};

const createDatabaseIndexes = async () => {
  try {
    // Create additional indexes for performance
    await Transaction.collection.createIndex({ createdAt: -1 });
    await User.collection.createIndex({ 'bank_details.verified': 1 });
    await Investment.collection.createIndex({ status: 1, end_date: 1 });
    await DashboardCache.collection.createIndex({ expires_at: 1 });
    console.log('✅ Database indexes created');
  } catch (error) {
    console.error('Error creating indexes:', error);
  }
};

const initializeRealTimeData = async () => {
  try {
    // Clear expired cache
    await DashboardCache.deleteMany({ expires_at: { $lt: new Date() } });
    
    // Initialize trending scores for plans
    const plans = await InvestmentPlan.find({});
    for (const plan of plans) {
      if (!plan.trending_score) {
        plan.trending_score = Math.floor(Math.random() * 100);
        plan.last_updated = new Date();
        await plan.save();
      }
    }
    
    console.log('✅ Real-time data initialized');
  } catch (error) {
    console.error('Error initializing real-time data:', error);
  }
};

// ==================== REAL-TIME CRON JOBS ====================

// Update real-time dashboard data every 30 seconds
cron.schedule('*/30 * * * * *', async () => {
  try {
    // Update trending scores for investment plans
    const plans = await InvestmentPlan.find({ is_active: true });
    for (const plan of plans) {
      // Simulate market fluctuations
      const fluctuation = (Math.random() - 0.5) * 2; // -1 to +1
      plan.trending_score = Math.max(0, Math.min(100, plan.trending_score + fluctuation));
      plan.last_updated = new Date();
      await plan.save();
    }
    
    // Update online users status
    const thirtySecondsAgo = new Date(Date.now() - 30000);
    await User.updateMany(
      { 
        online_status: true,
        last_seen: { $lt: thirtySecondsAgo }
      },
      { 
        online_status: false 
      }
    );
    
    // Broadcast to connected clients
    io.emit('market_update', {
      timestamp: new Date().toISOString(),
      message: 'Market data updated'
    });
    
  } catch (error) {
    console.error('Real-time cron job error:', error);
  }
});

// Clear old cache every hour
cron.schedule('0 * * * *', async () => {
  try {
    const oneHourAgo = new Date(Date.now() - 3600000);
    const deleted = await DashboardCache.deleteMany({
      last_updated: { $lt: oneHourAgo }
    });
    
    if (deleted.deletedCount > 0) {
      console.log(`🧹 Cleared ${deleted.deletedCount} old cache entries`);
    }
  } catch (error) {
    console.error('Cache cleanup error:', error);
  }
});

// ==================== ENHANCED ENDPOINTS (KEEPING ORIGINAL) ====================

// Health check with real-time stats
app.get('/health', async (req, res) => {
  const health = {
    success: true,
    status: 'OK',
    timestamp: new Date().toISOString(),
    version: '38.0.0',
    environment: config.nodeEnv,
    database: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
    real_time: {
      websocket_connections: connectedClients.size,
      socketio_connections: activeConnections.size,
      total_connections: connectedClients.size + activeConnections.size
    },
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

// Root endpoint
app.get('/', (req, res) => {
  res.json({
    success: true,
    message: '🚀 Raw Wealthy Backend API v38.0 - Real-Time Edition',
    version: '38.0.0',
    timestamp: new Date().toISOString(),
    status: 'Operational',
    environment: config.nodeEnv,
    real_time: {
      websocket: 'ws://' + req.get('host'),
      socketio: 'http://' + req.get('host') + '/socket.io',
      supported: true
    },
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
      realtime: '/api/realtime/*',
      forgot_password: '/api/auth/forgot-password',
      health: '/health'
    }
  });
});

// ==================== ENHANCED PROFILE ENDPOINT WITH REAL-TIME DATA ====================

// Get profile with real-time data
app.get('/api/profile', auth, async (req, res) => {
  try {
    const userId = req.user._id;
    
    // Get real-time dashboard data
    const realTimeData = await getRealTimeDashboardData(userId);
    
    if (!realTimeData) {
      return res.status(500).json(formatResponse(false, 'Failed to load profile data'));
    }
    
    // Get additional detailed data
    const [kyc, supportTickets, referralDetails] = await Promise.all([
      KYCSubmission.findOne({ user: userId }).lean(),
      SupportTicket.find({ user: userId })
        .sort({ createdAt: -1 })
        .limit(5)
        .lean(),
      Referral.find({ referrer: userId })
        .populate('referred_user', 'full_name email createdAt balance total_earnings')
        .sort({ createdAt: -1 })
        .lean()
    ]);
    
    const enhancedData = {
      ...realTimeData,
      detailed_info: {
        kyc_submission: kyc,
        support_tickets: supportTickets,
        referral_network: referralDetails,
        account_created: req.user.createdAt,
        last_password_change: req.user.updatedAt,
        security_level: calculateSecurityLevel(req.user)
      }
    };
    
    // Clear cache for fresh data next time
    await DashboardCache.findOneAndDelete({ user: userId });
    
    res.json(formatResponse(true, 'Profile retrieved successfully', enhancedData));
  } catch (error) {
    handleError(res, error, 'Error fetching profile');
  }
});

function calculateSecurityLevel(user) {
  let score = 0;
  if (user.password.length >= 12) score += 2;
  if (user.two_factor_enabled) score += 3;
  if (user.kyc_verified) score += 2;
  if (user.email_notifications) score += 1;
  
  if (score >= 6) return 'high';
  if (score >= 3) return 'medium';
  return 'low';
}

// ==================== ENHANCED INVESTMENT ENDPOINTS ====================

// Create investment with real-time updates
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
        } : null,
        created_via: 'api',
        realTime: true
      }
    });

    await investment.save();

    // Update user balance with real-time notification
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
      proofUrl,
      true // Real-time broadcast
    );

    // Update plan statistics
    await InvestmentPlan.findByIdAndUpdate(plan_id, {
      $inc: { 
        investment_count: 1,
        total_invested: investmentAmount,
        trending_score: 5 // Boost trending score
      },
      last_updated: new Date()
    });

    // Create notification with real-time delivery
    await createNotification(
      userId,
      'Investment Created',
      `Your investment of ₦${investmentAmount.toLocaleString()} in ${plan.name} has been created successfully.${proofUrl ? ' Awaiting admin approval.' : ''}`,
      'investment',
      '/investments',
      { amount: investmentAmount, plan_name: plan.name },
      true // Real-time delivery
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
          },
          true
        );
      }
    }

    // Clear dashboard cache for real-time update
    await DashboardCache.findOneAndDelete({ user: userId });

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
      },
      real_time_update: {
        websocket_event: 'investment_created',
        socketio_event: 'investment_update',
        broadcast: true
      }
    }));
  } catch (error) {
    handleError(res, error, 'Error creating investment');
  }
});

// ==================== ENHANCED DEPOSIT ENDPOINTS ====================

// Create deposit with real-time updates
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

    // Create deposit with enhanced fields
    const deposit = new Deposit({
      user: userId,
      amount: depositAmount,
      payment_method,
      status: 'pending',
      payment_proof_url: proofUrl,
      deposit_image_url: proofUrl,
      reference: generateReference('DEP'),
      remarks: remarks,
      processing_stage: 'submitted',
      estimated_completion: new Date(Date.now() + 24 * 60 * 60 * 1000), // 24 hours
      last_status_update: new Date(),
      metadata: {
        uploaded_file: uploadResult ? {
          filename: uploadResult.filename,
          size: uploadResult.size,
          mime_type: uploadResult.mimeType
        } : null,
        ip_address: req.ip,
        user_agent: req.headers['user-agent'],
        realTime: true
      }
    });

    await deposit.save();

    // Create notification with real-time delivery
    await createNotification(
      userId,
      'Deposit Request Submitted',
      `Your deposit request of ₦${depositAmount.toLocaleString()} has been submitted and is pending approval.`,
      'deposit',
      '/deposits',
      { amount: depositAmount, payment_method, has_proof: !!proofUrl },
      true
    );

    // Notify admin with real-time broadcast
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
        },
        true
      );
      
      // Real-time admin alert
      broadcastToUser(admin._id, 'admin_alert', {
        type: 'new_deposit',
        message: `New deposit request: ₦${depositAmount.toLocaleString()}`,
        deposit_id: deposit._id,
        user_name: req.user.full_name
      });
    }

    res.status(201).json(formatResponse(true, 'Deposit request submitted successfully!', { 
      deposit: {
        ...deposit.toObject(),
        formatted_amount: `₦${depositAmount.toLocaleString()}`,
        requires_approval: true,
        estimated_approval_time: '24-48 hours',
        proof_uploaded: !!proofUrl
      },
      real_time_updates: {
        websocket: true,
        socketio: true,
        notification_sent: true
      }
    }));
  } catch (error) {
    handleError(res, error, 'Error creating deposit');
  }
});

// ==================== ENHANCED ADMIN ENDPOINTS WITH REAL-TIME ====================

// Real-time admin dashboard
app.get('/api/admin/dashboard/realtime', adminAuth, async (req, res) => {
  try {
    const data = await getRealTimeAdminDashboard();
    
    if (!data) {
      return res.status(500).json(formatResponse(false, 'Failed to load admin dashboard'));
    }
    
    // Add real-time connections
    data.real_time.websocket_connections = connectedClients.size;
    data.real_time.socketio_connections = activeConnections.size;
    data.real_time.connected_users = Array.from(activeConnections.keys());
    
    res.json(formatResponse(true, 'Real-time admin dashboard loaded', data));
  } catch (error) {
    handleError(res, error, 'Error loading admin dashboard');
  }
});

// Real-time user monitoring
app.get('/api/admin/users/realtime', adminAuth, async (req, res) => {
  try {
    const { online_only = 'false', limit = 50 } = req.query;
    
    const query = {};
    if (online_only === 'true') {
      query.online_status = true;
    }
    
    const users = await User.find(query)
      .select('-password -two_factor_secret -verification_token -password_reset_token')
      .sort({ last_active: -1 })
      .limit(parseInt(limit))
      .lean();
    
    // Enhance with real-time data
    const enhancedUsers = users.map(user => {
      const isOnline = activeConnections.has(user._id.toString()) || connectedClients.has(user._id.toString());
      return {
        ...user,
        online_status: isOnline,
        connection_type: activeConnections.has(user._id.toString()) ? 'socketio' : 
                       connectedClients.has(user._id.toString()) ? 'websocket' : 'offline',
        last_seen_formatted: getTimeAgo(user.last_seen || user.last_active),
        activity_level: calculateActivityLevel(user)
      };
    });
    
    const stats = {
      total: users.length,
      online: enhancedUsers.filter(u => u.online_status).length,
      offline: enhancedUsers.filter(u => !u.online_status).length,
      active_now: enhancedUsers.filter(u => u.activity_level === 'high').length
    };
    
    res.json(formatResponse(true, 'Real-time user monitoring', {
      users: enhancedUsers,
      stats,
      last_updated: new Date().toISOString()
    }));
  } catch (error) {
    handleError(res, error, 'Error monitoring users');
  }
});

function calculateActivityLevel(user) {
  const now = new Date();
  const lastActive = new Date(user.last_active || user.last_seen);
  const hoursSinceActive = (now - lastActive) / (1000 * 60 * 60);
  
  if (hoursSinceActive < 1) return 'high';
  if (hoursSinceActive < 24) return 'medium';
  return 'low';
}

// Real-time system metrics
app.get('/api/admin/metrics', adminAuth, async (req, res) => {
  try {
    const metrics = {
      server: {
        uptime: process.uptime(),
        memory: process.memoryUsage(),
        cpu: process.cpuUsage(),
        pid: process.pid,
        platform: process.platform,
        node_version: process.version
      },
      
      database: {
        connections: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
        models: Object.keys(mongoose.connection.models),
        collections: await mongoose.connection.db.listCollections().toArray()
      },
      
      real_time: {
        websocket_clients: connectedClients.size,
        socketio_clients: activeConnections.size,
        active_rooms: io.sockets.adapter.rooms.size,
        sockets_connected: io.engine.clientsCount
      },
      
      performance: {
        response_time: Date.now(),
        requests_per_minute: 0, // Would need tracking
        error_rate: 0, // Would need tracking
        load_average: require('os').loadavg()
      },
      
      cache: {
        dashboard_cache_count: await DashboardCache.countDocuments({}),
        cache_hit_rate: 0, // Would need tracking
        memory_cache_size: 0
      }
    };
    
    res.json(formatResponse(true, 'System metrics', metrics));
  } catch (error) {
    handleError(res, error, 'Error getting system metrics');
  }
});

// ==================== REAL-TIME BROADCAST ENDPOINTS ====================

// Broadcast message to all users (admin only)
app.post('/api/admin/broadcast', adminAuth, [
  body('message').notEmpty().trim(),
  body('type').isIn(['info', 'warning', 'success', 'error']),
  body('target').optional().isIn(['all', 'online', 'specific']),
  body('user_ids').optional().isArray()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json(formatResponse(false, 'Validation failed'));
    }

    const { message, type = 'info', target = 'all', user_ids = [] } = req.body;
    const adminId = req.user._id;
    const admin = await User.findById(adminId);

    const broadcastData = {
      type: 'broadcast',
      message,
      broadcast_type: type,
      from_admin: admin.full_name,
      timestamp: new Date().toISOString(),
      action: 'system_notification'
    };

    let recipients = 0;

    if (target === 'all') {
      // Broadcast to all connected clients
      io.emit('admin_broadcast', broadcastData);
      
      // Also send via WebSocket
      for (const ws of connectedClients.values()) {
        if (ws.readyState === WebSocket.OPEN) {
          ws.send(JSON.stringify(broadcastData));
          recipients++;
        }
      }
      
      // Create notifications for all users
      const users = await User.find({ is_active: true });
      for (const user of users) {
        await createNotification(
          user._id,
          'System Broadcast',
          message,
          type,
          null,
          { broadcast: true, admin: admin.full_name },
          false // Don't send real-time (already sent via broadcast)
        );
      }
      
    } else if (target === 'online') {
      // Broadcast only to online users
      const onlineUserIds = Array.from(activeConnections.keys());
      
      for (const userId of onlineUserIds) {
        io.to(`user_${userId}`).emit('admin_broadcast', broadcastData);
        
        const wsClient = connectedClients.get(userId);
        if (wsClient && wsClient.readyState === WebSocket.OPEN) {
          wsClient.send(JSON.stringify(broadcastData));
        }
        
        await createNotification(
          userId,
          'System Broadcast',
          message,
          type,
          null,
          { broadcast: true, admin: admin.full_name },
          false
        );
        
        recipients++;
      }
      
    } else if (target === 'specific' && user_ids.length > 0) {
      // Broadcast to specific users
      for (const userId of user_ids) {
        const user = await User.findById(userId);
        if (user && user.is_active) {
          io.to(`user_${userId}`).emit('admin_broadcast', broadcastData);
          
          const wsClient = connectedClients.get(userId);
          if (wsClient && wsClient.readyState === WebSocket.OPEN) {
            wsClient.send(JSON.stringify(broadcastData));
          }
          
          await createNotification(
            userId,
            'System Broadcast',
            message,
            type,
            null,
            { broadcast: true, admin: admin.full_name },
            false
          );
          
          recipients++;
        }
      }
    }

    // Create audit log
    await createAdminAudit(
      adminId,
      'BROADCAST_MESSAGE',
      'system',
      null,
      {
        message,
        type,
        target,
        recipients,
        user_ids: target === 'specific' ? user_ids : undefined
      },
      req.ip,
      req.headers['user-agent'],
      true // Broadcast to other admins
    );

    res.json(formatResponse(true, 'Broadcast sent successfully', {
      recipients,
      target,
      message_length: message.length,
      delivery_time: new Date().toISOString()
    }));
  } catch (error) {
    handleError(res, error, 'Error sending broadcast');
  }
});

// Send real-time notification to user (admin only)
app.post('/api/admin/notify', adminAuth, [
  body('user_id').notEmpty(),
  body('title').notEmpty().trim(),
  body('message').notEmpty().trim(),
  body('type').isIn(['info', 'success', 'warning', 'error', 'promotional']),
  body('action_url').optional().trim()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json(formatResponse(false, 'Validation failed'));
    }

    const { user_id, title, message, type, action_url } = req.body;
    const adminId = req.user._id;

    const user = await User.findById(user_id);
    if (!user) {
      return res.status(404).json(formatResponse(false, 'User not found'));
    }

    // Create and send notification with real-time delivery
    const notification = await createNotification(
      user_id,
      title,
      message,
      type,
      action_url,
      {
        sent_by_admin: true,
        admin_id: adminId,
        admin_name: req.user.full_name
      },
      true
    );

    // Create audit log
    await createAdminAudit(
      adminId,
      'SEND_USER_NOTIFICATION',
      'user',
      user_id,
      {
        user_name: user.full_name,
        title,
        message,
        type,
        notification_id: notification?._id
      },
      req.ip,
      req.headers['user-agent'],
      true
    );

    res.json(formatResponse(true, 'Notification sent successfully', {
      notification_id: notification?._id,
      user_name: user.full_name,
      delivered_via_socket: notification?.delivered_via_socket || false,
      delivery_time: new Date().toISOString()
    }));
  } catch (error) {
    handleError(res, error, 'Error sending notification');
  }
});

// ==================== SOCKET.IO EVENT HANDLERS ====================

// Socket.IO event handling
io.on('connection', (socket) => {
  // Existing authentication handler...
  
  // Handle custom events from clients
  socket.on('get_dashboard', async (data) => {
    try {
      const userId = socket.userId || data.userId;
      if (userId) {
        const dashboardData = await getRealTimeDashboardData(userId);
        socket.emit('dashboard_data', dashboardData);
      }
    } catch (error) {
      console.error('Error getting dashboard:', error);
      socket.emit('error', { message: 'Failed to load dashboard' });
    }
  });
  
  socket.on('mark_notification_read', async (notificationId) => {
    try {
      await Notification.findByIdAndUpdate(notificationId, {
        is_read: true,
        read_at: new Date()
      });
      socket.emit('notification_marked_read', { notificationId });
    } catch (error) {
      console.error('Error marking notification read:', error);
    }
  });
  
  socket.on('ping', (data) => {
    socket.emit('pong', {
      timestamp: new Date().toISOString(),
      server_time: Date.now()
    });
  });
  
  socket.on('subscribe', (channel) => {
    socket.join(channel);
    socket.emit('subscribed', { channel });
  });
  
  socket.on('unsubscribe', (channel) => {
    socket.leave(channel);
    socket.emit('unsubscribed', { channel });
  });
});

// ==================== REAL-TIME UPDATE SERVICE ====================

// Service to send periodic updates to connected clients
setInterval(async () => {
  try {
    // Send updates to all connected clients
    for (const [userId, socketId] of activeConnections.entries()) {
      try {
        const socket = io.sockets.sockets.get(socketId);
        if (socket) {
          // Send lightweight update
          const update = {
            type: 'heartbeat',
            timestamp: new Date().toISOString(),
            server_time: Date.now()
          };
          
          socket.emit('heartbeat', update);
        }
      } catch (error) {
        console.error(`Error sending heartbeat to user ${userId}:`, error);
      }
    }
    
    // Check for users needing dashboard updates
    const oneMinuteAgo = new Date(Date.now() - 60000);
    const usersNeedingUpdate = await User.find({
      last_dashboard_update: { $lt: oneMinuteAgo },
      is_active: true
    }).limit(10);
    
    for (const user of usersNeedingUpdate) {
      if (activeConnections.has(user._id.toString())) {
        const dashboardData = await getRealTimeDashboardData(user._id);
        if (dashboardData) {
          io.to(`user_${user._id}`).emit('dashboard_update', dashboardData);
        }
      }
    }
    
  } catch (error) {
    console.error('Real-time update service error:', error);
  }
}, 30000); // Every 30 seconds

// ==================== ENHANCED ERROR HANDLING ====================

// 404 handler
app.use((req, res) => {
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
      '/api/realtime/*',
      '/health'
    ],
    real_time_endpoints: {
      websocket: 'Connect via WebSocket',
      socketio: 'Connect via Socket.IO',
      events: ['dashboard_update', 'notification', 'transaction_update', 'heartbeat']
    }
  }));
});

// Global error handler
app.use((err, req, res, next) => {
  console.error('Global error:', err);
  
  // Log error for debugging
  const errorLog = {
    timestamp: new Date().toISOString(),
    url: req.originalUrl,
    method: req.method,
    ip: req.ip,
    user_agent: req.headers['user-agent'],
    user_id: req.userId || 'anonymous',
    error: {
      message: err.message,
      stack: config.nodeEnv === 'development' ? err.stack : undefined,
      name: err.name,
      code: err.code
    }
  };
  
  console.error('Error details:', errorLog);
  
  // Broadcast critical errors to admins
  if (err.statusCode >= 500) {
    broadcastToAdmin('system_error', {
      error: err.message,
      endpoint: req.originalUrl,
      timestamp: new Date().toISOString()
    });
  }
  
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
  
  // WebSocket errors
  if (err.code === 'WS_ERR') {
    return res.status(400).json(formatResponse(false, 'WebSocket error occurred'));
  }
  
  res.status(500).json(formatResponse(false, 'Internal server error', {
    error_id: crypto.randomBytes(8).toString('hex'),
    timestamp: new Date().toISOString(),
    support_contact: 'support@rawwealthy.com'
  }));
});

// ==================== SERVER INITIALIZATION ====================

const startServer = async () => {
  try {
    // Initialize database
    await initializeDatabase();
    
    // Start server
    server.listen(config.port, '0.0.0.0', () => {
      console.log(`
🎯 RAW WEALTHY BACKEND v38.0 - REAL-TIME DASHBOARD EDITION
=========================================================
🌐 Server running on port ${config.port}
🚀 Environment: ${config.nodeEnv}
📊 Health Check: /health
🔗 API Base: /api
⚡ Real-time: /api/realtime/*
💾 Database: MongoDB Connected
🔌 WebSocket: Ready (${connectedClients.size} connections)
📡 Socket.IO: Ready (${activeConnections.size} connections)
🛡️ Security: Enhanced Protection
📧 Email: ${config.emailEnabled ? '✅ Enabled' : '❌ Disabled'}
📁 Uploads: ${config.uploadDir}
🌐 Server URL: ${config.serverURL}

✅ REAL-TIME FEATURES:
   ⚡ Live Dashboard Updates Every 30 Seconds
   🔌 WebSocket & Socket.IO Support
   📊 Real-time Market Data
   💰 Live Balance Updates
   📈 Investment Progress Tracking
   🔔 Instant Notifications
   👥 Online User Monitoring
   📡 Admin Real-time Dashboard
   🎯 User Activity Stream
   📱 Multi-connection Support
   🔄 Auto-refresh Data
   📊 Performance Metrics
   🚨 System Alerts
   📈 Trending Investments
   💹 Market Fluctuations
   ⏱️ Server Time Sync
   🔄 Heartbeat Service
   📡 Broadcast System
   🛡️ Connection Security

✅ ENHANCED DASHBOARD:
   📊 Real-time Financial Summary
   📈 Live Investment Performance
   💰 Instant Balance Updates
   🔔 Push Notifications
   📱 Responsive Data Stream
   📊 Performance Analytics
   🎯 User Activity Feed
   📈 Market Trends
   💹 ROI Calculator
   ⏱️ Time-sensitive Updates

✅ ADMIN REAL-TIME FEATURES:
   📡 Live User Monitoring
   ⚡ Instant Alerts
   📊 System Metrics
   🔄 Auto-refresh Data
   📈 Performance Analytics
   🚨 Critical Notifications
   👥 Online Status Tracking
   📊 Real-time Charts
   🔔 Admin Broadcast
   📱 Multi-admin Support

🚀 FULLY CONNECTED & REAL-TIME READY!
🔐 SECURE WEBSOCKET CONNECTIONS
📈 LIVE DATA STREAMS
📱 INSTANT FRONTEND UPDATES
🎯 PRODUCTION OPTIMIZED
      `);
    });

    // Graceful shutdown
    const gracefulShutdown = async (signal) => {
      console.log(`\n${signal} received, shutting down gracefully...`);
      
      // Update all users offline
      await User.updateMany(
        { online_status: true },
        { online_status: false, last_seen: new Date() }
      );
      
      // Close WebSocket connections
      for (const [userId, ws] of connectedClients.entries()) {
        ws.close(1001, 'Server shutting down');
      }
      connectedClients.clear();
      
      // Close Socket.IO
      io.close();
      
      // Close server
      server.close(async () => {
        console.log('HTTP server closed');
        
        // Close database connection
        try {
          await mongoose.connection.close();
          console.log('Database connection closed');
        } catch (dbError) {
          console.error('Error closing database:', dbError);
        }
        
        console.log('Process terminated gracefully');
        process.exit(0);
      });
      
      // Force shutdown after 10 seconds
      setTimeout(() => {
        console.error('Could not close connections in time, forcefully shutting down');
        process.exit(1);
      }, 10000);
    };

    // Handle different shutdown signals
    process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
    process.on('SIGINT', () => gracefulShutdown('SIGINT'));
    process.on('SIGUSR2', () => gracefulShutdown('SIGUSR2')); // For nodemon

    // Handle uncaught exceptions
    process.on('uncaughtException', (error) => {
      console.error('Uncaught Exception:', error);
      gracefulShutdown('uncaughtException');
    });

    process.on('unhandledRejection', (reason, promise) => {
      console.error('Unhandled Rejection at:', promise, 'reason:', reason);
      // Don't crash the process for unhandled rejections
    });

  } catch (error) {
    console.error('❌ Server initialization failed:', error);
    process.exit(1);
  }
};

// Start the server
startServer();

export default app;
