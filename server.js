// server.js - RAW WEALTHY BACKEND v51.0 - ULTIMATE PRODUCTION EDITION
// ENHANCED WITH IMMEDIATE DAILY INTEREST & ADVANCED ADMIN CONTROLS
// DAILY INTEREST UPDATES IMMEDIATELY AFTER ADMIN APPROVAL & EVERY 24 HOURS
// ALL WITHDRAWALS REQUIRE ADMIN APPROVAL WITH REJECTION CAPABILITY
// ENHANCED INVESTMENT INTEREST RATES: 15% for 3500, +5% for others
// ADMIN CAN REJECT/USER MANAGEMENT SYSTEM
// READY FOR PRODUCTION DEPLOYMENT

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
import { Server } from 'socket.io';
import http from 'http';

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
    
    if (!process.env.JWT_SECRET) {
        process.env.JWT_SECRET = crypto.randomBytes(64).toString('hex');
        console.log('✅ Generated JWT_SECRET automatically');
    }
    
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
    
    // Payment Integration
    paymentEnabled: process.env.FLUTTERWAVE_PUBLIC_KEY && process.env.FLUTTERWAVE_SECRET_KEY,
    paymentConfig: {
        flutterwave: {
            publicKey: process.env.FLUTTERWAVE_PUBLIC_KEY,
            secretKey: process.env.FLUTTERWAVE_SECRET_KEY,
            encryptionKey: process.env.FLUTTERWAVE_ENCRYPTION_KEY
        },
        paystack: {
            publicKey: process.env.PAYSTACK_PUBLIC_KEY,
            secretKey: process.env.PAYSTACK_SECRET_KEY
        }
    },
    
    // Business Logic - UPDATED INTEREST RATES
    minInvestment: parseInt(process.env.MIN_INVESTMENT) || 3500,
    minDeposit: parseInt(process.env.MIN_DEPOSIT) || 3500,
    minWithdrawal: parseInt(process.env.MIN_WITHDRAWAL) || 3500,
    maxWithdrawalPercent: parseFloat(process.env.MAX_WITHDRAWAL_PERCENT) || 100,
    
    platformFeePercent: parseFloat(process.env.PLATFORM_FEE_PERCENT) || 10,
    referralCommissionPercent: parseFloat(process.env.REFERRAL_COMMISSION_PERCENT) || 10,
    welcomeBonus: parseInt(process.env.WELCOME_BONUS) || 100,
    
    // ENHANCED FEATURES
    dailyInterestTime: process.env.DAILY_INTEREST_TIME || '00:00',
    withdrawalAutoApprove: process.env.WITHDRAWAL_AUTO_APPROVE === 'true' ? true : false, // Force admin approval
    referralCommissionOnFirstInvestment: true,
    
    // Interest Rate Configuration
    baseInterestRate: 15, // Base interest rate for 3500 investment
    interestRateIncrement: 5, // Increment for higher tiers
    
    // Storage
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

console.log('⚙️ Enhanced Configuration Loaded:');
console.log(`- Port: ${config.port}`);
console.log(`- Environment: ${config.nodeEnv}`);
console.log(`- Client URL: ${config.clientURL}`);
console.log(`- Server URL: ${config.serverURL}`);
console.log(`- Base Interest Rate: ${config.baseInterestRate}%`);
console.log(`- Interest Rate Increment: +${config.interestRateIncrement}%`);
console.log(`- Withdrawal Auto-approve: ${config.withdrawalAutoApprove}`);
console.log(`- All Withdrawals Require Admin Approval: true`);

// ==================== ENHANCED EXPRESS SETUP WITH SOCKET.IO ====================
const app = express();
const server = http.createServer(app);
const io = new Server(server, {
    cors: {
        origin: config.allowedOrigins,
        credentials: true
    }
});

// Real-time connection handling
io.on('connection', (socket) => {
    console.log(`🔌 New socket connection: ${socket.id}`);
    
    socket.on('join-user', (userId) => {
        socket.join(`user-${userId}`);
        console.log(`👤 User ${userId} joined their room`);
    });
    
    socket.on('admin-join', (adminId) => {
        socket.join(`admin-${adminId}`);
        socket.join('admin-room');
        socket.join('withdrawal-approvals');
        socket.join('investment-monitor');
        socket.join('user-management');
        console.log(`👨‍💼 Admin ${adminId} joined admin room`);
    });
    
    socket.on('disconnect', () => {
        console.log(`🔌 Socket disconnected: ${socket.id}`);
    });
});

// Socket.IO utility functions
const emitToUser = (userId, event, data) => {
    io.to(`user-${userId}`).emit(event, data);
};

const emitToAdmins = (event, data) => {
    io.to('admin-room').emit(event, data);
};

const emitToUserManagement = (event, data) => {
    io.to('user-management').emit(event, data);
};

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
    createAccount: createRateLimiter(60 * 60 * 1000, 10, 'Too many accounts created from this IP'),
    auth: createRateLimiter(15 * 60 * 1000, 20, 'Too many authentication attempts'),
    api: createRateLimiter(15 * 60 * 1000, 1000, 'Too many requests from this IP'),
    financial: createRateLimiter(15 * 60 * 1000, 50, 'Too many financial operations'),
    passwordReset: createRateLimiter(15 * 60 * 1000, 5, 'Too many password reset attempts'),
    admin: createRateLimiter(15 * 60 * 1000, 500, 'Too many admin requests')
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
        const fileExtension = config.allowedMimeTypes[file.mimetype] || file.originalname.split('.').pop();
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

if (!fs.existsSync(config.uploadDir)) {
    fs.mkdirSync(config.uploadDir, { recursive: true });
    console.log('📁 Created uploads directory');
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

// ==================== DATABASE MODELS - UPDATED WITH ENHANCED FEATURES ====================
const userSchema = new mongoose.Schema({
    full_name: { type: String, required: true, trim: true },
    email: { type: String, required: true, unique: true, lowercase: true },
    phone: { type: String, required: true },
    password: { type: String, required: true, select: false },
    role: { type: String, enum: ['user', 'admin', 'super_admin'], default: 'user' },
    
    // Financial fields
    balance: { type: Number, default: 0, min: 0 },
    total_earnings: { type: Number, default: 0, min: 0 },
    referral_earnings: { type: Number, default: 0, min: 0 },
    daily_earnings: { type: Number, default: 0, min: 0 },
    total_withdrawn: { type: Number, default: 0, min: 0 },
    withdrawable_earnings: { type: Number, default: 0, min: 0 },
    
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
    
    // Enhanced dashboard fields
    total_deposits: { type: Number, default: 0 },
    total_withdrawals: { type: Number, default: 0 },
    total_investments: { type: Number, default: 0 },
    last_deposit_date: Date,
    last_withdrawal_date: Date,
    last_investment_date: Date,
    last_daily_interest_date: Date,
    
    // First investment tracking for referral commissions
    first_investment_amount: { type: Number, default: 0 },
    first_investment_date: Date,
    referral_commission_paid: { type: Boolean, default: false },
    
    // User status tracking for admin
    account_status: { 
        type: String, 
        enum: ['active', 'suspended', 'banned', 'deactivated'], 
        default: 'active' 
    },
    suspension_reason: String,
    suspension_end_date: Date,
    banned_by: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    banned_at: Date,
    
    // Login location tracking for security
    login_history: [{
        ip: String,
        location: String,
        device: String,
        timestamp: { type: Date, default: Date.now }
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
            
            ret.available_for_withdrawal = doc.available_for_withdrawal;
            ret.portfolio_value = doc.portfolio_value;
            return ret;
        }
    },
    toObject: { virtuals: true }
});

// Virtual field for available withdrawal
userSchema.virtual('available_for_withdrawal').get(function() {
    return Math.max(0, this.withdrawable_earnings || 0);
});

// Virtual field for portfolio value
userSchema.virtual('portfolio_value').get(function() {
    return (this.balance || 0);
});

// Indexes
userSchema.index({ email: 1 }, { unique: true });
userSchema.index({ referral_code: 1 }, { unique: true, sparse: true });
userSchema.index({ is_active: 1, role: 1, kyc_status: 1 });
userSchema.index({ withdrawable_earnings: 1 });
userSchema.index({ account_status: 1 });

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
    
    // Update withdrawable earnings whenever earnings change
    if (this.isModified('total_earnings') || this.isModified('referral_earnings') || this.isModified('total_withdrawn')) {
        this.withdrawable_earnings = Math.max(0, 
            (this.total_earnings || 0) + 
            (this.referral_earnings || 0) - 
            (this.total_withdrawn || 0)
        );
    }
    
    // Update is_active based on account_status
    if (this.isModified('account_status')) {
        this.is_active = this.account_status === 'active';
    }
    
    next();
});

// Methods
userSchema.methods.comparePassword = async function(candidatePassword) {
    try {
        return await bcrypt.compare(candidatePassword, this.password);
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
            kyc_verified: this.kyc_verified,
            balance: this.balance,
            total_earnings: this.total_earnings,
            referral_earnings: this.referral_earnings,
            account_status: this.account_status
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

userSchema.methods.getAvailableForWithdrawal = function() {
    return Math.max(0, this.withdrawable_earnings || 0);
};

const User = mongoose.model('User', userSchema);

// Investment Plan Model - UPDATED INTEREST RATES
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
    category: { type: String, enum: ['agriculture', 'mining', 'energy', 'metals', 'crypto', 'real_estate', 'precious_stones', 'livestock', 'timber', 'aquaculture'], default: 'agriculture' },
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

// Investment Model - ENHANCED with immediate interest after approval
const investmentSchema = new mongoose.Schema({
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    plan: { type: mongoose.Schema.Types.ObjectId, ref: 'InvestmentPlan', required: true },
    amount: { type: Number, required: true, min: config.minInvestment },
    status: { type: String, enum: ['pending', 'active', 'completed', 'cancelled', 'failed'], default: 'pending' },
    start_date: { type: Date, default: Date.now },
    end_date: { type: Date, required: true },
    approved_at: Date,
    
    // Enhanced earnings tracking with immediate interest
    expected_earnings: { type: Number, required: true },
    earned_so_far: { type: Number, default: 0 },
    daily_earnings: { type: Number, default: 0 },
    last_earning_date: Date,
    next_interest_date: Date, // When next interest should be added
    interest_added_count: { type: Number, default: 0 },
    total_interest_days: { type: Number, default: 0 },
    remaining_days: { type: Number, default: 0 }, // Track remaining days
    
    // Immediate interest tracking
    immediate_interest_added: { type: Boolean, default: false },
    immediate_interest_amount: { type: Number, default: 0 },
    
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
investmentSchema.index({ next_interest_date: 1 });
investmentSchema.index({ immediate_interest_added: 1 });
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

// Withdrawal Model - ALL WITHDRAWALS REQUIRE ADMIN APPROVAL
const withdrawalSchema = new mongoose.Schema({
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    amount: { type: Number, required: true, min: config.minWithdrawal },
    payment_method: { type: String, enum: ['bank_transfer', 'crypto', 'paypal'], required: true },
    
    // Earnings breakdown
    from_earnings: { type: Number, default: 0 },
    from_referral: { type: Number, default: 0 },
    
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
    
    // All withdrawals require admin approval
    status: { type: String, enum: ['pending', 'approved', 'rejected', 'paid', 'processing'], default: 'pending' },
    reference: { type: String, unique: true, sparse: true },
    admin_notes: String,
    approved_by: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    approved_at: Date,
    paid_at: Date,
    transaction_id: String,
    
    // Force admin approval
    auto_approved: { type: Boolean, default: false },
    requires_admin_approval: { type: Boolean, default: true },
    
    // Additional fields for admin review
    admin_review_status: { 
        type: String, 
        enum: ['pending_review', 'under_review', 'approved', 'rejected'], 
        default: 'pending_review' 
    },
    reviewed_by: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    review_notes: String,
    review_date: Date,
    
    // Rejection details
    rejection_reason: String,
    rejected_by: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    rejected_at: Date,
    
    metadata: { type: mongoose.Schema.Types.Mixed, default: {} }
}, {
    timestamps: true
});

withdrawalSchema.index({ user: 1, status: 1 });
withdrawalSchema.index({ admin_review_status: 1 });
const Withdrawal = mongoose.model('Withdrawal', withdrawalSchema);

// Transaction Model
const transactionSchema = new mongoose.Schema({
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    type: { type: String, enum: ['deposit', 'withdrawal', 'investment', 'daily_interest', 'referral_bonus', 'bonus', 'fee', 'refund', 'transfer'], required: true },
    amount: { type: Number, required: true },
    description: { type: String, required: true },
    reference: { type: String, unique: true, sparse: true },
    status: { type: String, enum: ['pending', 'completed', 'failed', 'cancelled'], default: 'completed' },
    
    balance_before: Number,
    balance_after: Number,
    earnings_before: Number,
    earnings_after: Number,
    referral_earnings_before: Number,
    referral_earnings_after: Number,
    withdrawable_before: Number,
    withdrawable_after: Number,
    
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

kycSubmissionSchema.index({ status: 1 });
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

supportTicketSchema.index({ user: 1, status: 1 });
const SupportTicket = mongoose.model('SupportTicket', supportTicketSchema);

// Referral Model
const referralSchema = new mongoose.Schema({
    referrer: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    referred_user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, unique: true },
    referral_code: { type: String, required: true },
    status: { type: String, enum: ['pending', 'active', 'completed', 'expired'], default: 'pending' },
    
    total_commission: { type: Number, default: 0 },
    commission_percentage: { type: Number, default: config.referralCommissionPercent },
    
    investment_amount: Number,
    earnings_paid: { type: Boolean, default: false },
    paid_at: Date,
    
    first_investment_commission_paid: { type: Boolean, default: false },
    first_investment_amount: Number,
    first_investment_date: Date,
    
    metadata: { type: mongoose.Schema.Types.Mixed, default: {} }
}, {
    timestamps: true
});

referralSchema.index({ referrer: 1, status: 1 });
referralSchema.index({ referred_user: 1 });
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

notificationSchema.index({ user: 1, is_read: 1 });
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

// AML Monitoring Model
const amlMonitoringSchema = new mongoose.Schema({
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    transaction_id: mongoose.Schema.Types.ObjectId,
    transaction_type: String,
    amount: Number,
    flagged_reason: String,
    risk_score: { type: Number, min: 0, max: 100 },
    status: { type: String, enum: ['pending_review', 'cleared', 'blocked', 'suspicious'], default: 'pending_review' },
    reviewed_by: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    reviewed_at: Date,
    notes: String,
    metadata: { type: mongoose.Schema.Types.Mixed, default: {} }
}, {
    timestamps: true
});

amlMonitoringSchema.index({ status: 1, risk_score: -1 });
const AmlMonitoring = mongoose.model('AmlMonitoring', amlMonitoringSchema);

// ==================== UTILITY FUNCTIONS - ENHANCED ====================
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
        
        // Emit real-time notification
        emitToUser(userId, 'new-notification', {
            title,
            message,
            type,
            action_url: actionUrl
        });
        
        // Send email if enabled
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

// ==================== ENHANCED createTransaction FUNCTION ====================
const createTransaction = async (userId, type, amount, description, status = 'completed', metadata = {}) => {
    console.log(`🔄 [TRANSACTION] Creating: ${type} for user ${userId}, amount: ${amount}, status: ${status}`);
    
    const session = await mongoose.startSession();
    
    try {
        await session.withTransaction(async () => {
            // Get fresh user data with session
            const user = await User.findById(userId).session(session);
            if (!user) {
                throw new Error(`User ${userId} not found`);
            }
            
            // Store before values
            const beforeState = {
                balance: user.balance || 0,
                total_earnings: user.total_earnings || 0,
                referral_earnings: user.referral_earnings || 0,
                withdrawable_earnings: user.withdrawable_earnings || 0,
                total_withdrawn: user.total_withdrawn || 0
            };
            
            console.log(`📊 [TRANSACTION] Before state:`, beforeState);
            
            // Process transaction based on type
            if (status === 'completed') {
                switch (type) {
                    case 'daily_interest':
                        if (amount > 0) {
                            user.total_earnings = beforeState.total_earnings + amount;
                            user.withdrawable_earnings = beforeState.withdrawable_earnings + amount;
                            user.balance = beforeState.balance + amount;
                            console.log(`💰 Added ${amount} to total_earnings and withdrawable_earnings`);
                        }
                        break;
                        
                    case 'referral_bonus':
                        if (amount > 0) {
                            user.referral_earnings = beforeState.referral_earnings + amount;
                            user.withdrawable_earnings = beforeState.withdrawable_earnings + amount;
                            user.balance = beforeState.balance + amount;
                            console.log(`🎁 Added ${amount} to referral_earnings and withdrawable_earnings`);
                        }
                        break;
                        
                    case 'investment':
                        // Amount is negative for investment
                        const investmentAmount = Math.abs(amount);
                        user.balance = Math.max(0, beforeState.balance - investmentAmount);
                        user.total_investments = (user.total_investments || 0) + investmentAmount;
                        user.last_investment_date = new Date();
                        
                        // Track first investment
                        if (!user.first_investment_amount || user.first_investment_amount === 0) {
                            user.first_investment_amount = investmentAmount;
                            user.first_investment_date = new Date();
                        }
                        
                        console.log(`📈 Deducted ${investmentAmount} from balance for investment`);
                        break;
                        
                    case 'deposit':
                        if (amount > 0) {
                            user.balance = beforeState.balance + amount;
                            user.total_deposits = (user.total_deposits || 0) + amount;
                            user.last_deposit_date = new Date();
                            console.log(`💵 Added ${amount} to balance from deposit`);
                        }
                        break;
                        
                    case 'withdrawal':
                        // Amount is negative for withdrawal
                        const withdrawalAmount = Math.abs(amount);
                        const fromEarnings = metadata.from_earnings || 0;
                        const fromReferral = metadata.from_referral || 0;
                        
                        user.total_earnings = Math.max(0, beforeState.total_earnings - fromEarnings);
                        user.referral_earnings = Math.max(0, beforeState.referral_earnings - fromReferral);
                        user.withdrawable_earnings = Math.max(0, beforeState.withdrawable_earnings - (fromEarnings + fromReferral));
                        user.total_withdrawn = beforeState.total_withdrawn + withdrawalAmount;
                        user.balance = Math.max(0, beforeState.balance - withdrawalAmount);
                        user.total_withdrawals = (user.total_withdrawals || 0) + withdrawalAmount;
                        user.last_withdrawal_date = new Date();
                        
                        console.log(`💸 Withdrew ${withdrawalAmount} (Earnings: ${fromEarnings}, Referral: ${fromReferral})`);
                        break;
                        
                    case 'bonus':
                        if (amount > 0) {
                            user.balance = beforeState.balance + amount;
                            console.log(`🎉 Added ${amount} bonus to balance`);
                        }
                        break;
                }
            }
            
            // Save user changes
            await user.save({ session });
            console.log(`✅ [TRANSACTION] User updated successfully`);
            
            // Create transaction record
            const afterState = {
                balance: user.balance,
                total_earnings: user.total_earnings,
                referral_earnings: user.referral_earnings,
                withdrawable_earnings: user.withdrawable_earnings,
                total_withdrawn: user.total_withdrawn
            };
            
            const transaction = new Transaction({
                user: userId,
                type,
                amount,
                description,
                status,
                reference: generateReference('TXN'),
                balance_before: beforeState.balance,
                balance_after: afterState.balance,
                earnings_before: beforeState.total_earnings,
                earnings_after: afterState.total_earnings,
                referral_earnings_before: beforeState.referral_earnings,
                referral_earnings_after: afterState.referral_earnings,
                withdrawable_before: beforeState.withdrawable_earnings,
                withdrawable_after: afterState.withdrawable_earnings,
                metadata: {
                    ...metadata,
                    processedAt: new Date(),
                    user_id: userId,
                    transaction_type: type,
                    debug: {
                        before: beforeState,
                        after: afterState,
                        change: {
                            balance: afterState.balance - beforeState.balance,
                            total_earnings: afterState.total_earnings - beforeState.total_earnings,
                            referral_earnings: afterState.referral_earnings - beforeState.referral_earnings,
                            withdrawable_earnings: afterState.withdrawable_earnings - beforeState.withdrawable_earnings
                        }
                    }
                }
            });
            
            await transaction.save({ session });
            console.log(`✅ [TRANSACTION] Transaction record created: ${transaction._id}`);
            
            // Emit real-time update
            emitToUser(userId, 'balance-updated', {
                balance: afterState.balance,
                total_earnings: afterState.total_earnings,
                referral_earnings: afterState.referral_earnings,
                withdrawable_earnings: afterState.withdrawable_earnings,
                total_withdrawn: afterState.total_withdrawn,
                timestamp: new Date().toISOString()
            });
            
            console.log(`📊 [TRANSACTION] Final state:`, afterState);
        });
        
        console.log(`🎯 [TRANSACTION] Completed successfully for user ${userId}`);
        return { success: true };
        
    } catch (error) {
        console.error(`❌ [TRANSACTION] Failed:`, error);
        return { success: false, error: error.message };
    } finally {
        session.endSession();
    }
};

// ==================== ENHANCED DAILY INTEREST CALCULATION ====================
const calculateDailyInterest = async () => {
    console.log('🔄 Running enhanced daily interest calculation...');
    
    try {
        // Get all active investments that have passed their next interest date
        const now = new Date();
        const activeInvestments = await Investment.find({
            status: 'active',
            end_date: { $gt: now },
            $or: [
                { next_interest_date: { $lte: now } },
                { next_interest_date: { $exists: false } }
            ]
        }).populate('plan', 'daily_interest name').populate('user');
        
        let totalInterestPaid = 0;
        let investmentsUpdated = 0;
        
        for (const investment of activeInvestments) {
            if (investment.plan && investment.plan.daily_interest) {
                const dailyEarning = (investment.amount * investment.plan.daily_interest) / 100;
                
                // Check if investment hasn't expired
                if (investment.end_date > now) {
                    // Update investment
                    investment.earned_so_far += dailyEarning;
                    investment.interest_added_count += 1;
                    investment.last_earning_date = now;
                    
                    // Calculate remaining days
                    const timeRemaining = investment.end_date - now;
                    const daysRemaining = Math.ceil(timeRemaining / (1000 * 60 * 60 * 24));
                    investment.remaining_days = Math.max(0, daysRemaining);
                    
                    // Set next interest date to 24 hours from now
                    investment.next_interest_date = new Date(now.getTime() + 24 * 60 * 60 * 1000);
                    
                    // If this is the first interest after immediate interest, set total interest days
                    if (!investment.total_interest_days) {
                        investment.total_interest_days = investment.plan.duration;
                    }
                    
                    await investment.save();
                    
                    // Credit user's earnings
                    await createTransaction(
                        investment.user._id,
                        'daily_interest',
                        dailyEarning,
                        `Daily interest from ${investment.plan.name} investment`,
                        'completed',
                        {
                            investment_id: investment._id,
                            plan_name: investment.plan.name,
                            daily_interest_rate: investment.plan.daily_interest,
                            investment_amount: investment.amount,
                            interest_day: investment.interest_added_count,
                            total_days: investment.total_interest_days,
                            remaining_days: investment.remaining_days
                        }
                    );
                    
                    totalInterestPaid += dailyEarning;
                    investmentsUpdated++;
                    
                    // Check if investment has completed all interest days
                    if (investment.interest_added_count >= investment.total_interest_days) {
                        investment.status = 'completed';
                        await investment.save();
                        
                        await createNotification(
                            investment.user._id,
                            'Investment Completed',
                            `Your investment in ${investment.plan.name} has completed. Total earnings: ₦${investment.earned_so_far.toLocaleString()}`,
                            'investment',
                            '/investments'
                        );
                    }
                }
            }
        }
        
        console.log(`✅ Enhanced daily interest calculation completed: ${investmentsUpdated} investments updated, ₦${totalInterestPaid.toLocaleString()} paid`);
        
        return {
            success: true,
            investmentsUpdated,
            totalInterestPaid
        };
    } catch (error) {
        console.error('❌ Error in enhanced daily interest calculation:', error);
        return {
            success: false,
            error: error.message
        };
    }
};

// ==================== ADD IMMEDIATE INTEREST FUNCTION ====================
const addImmediateInterest = async (investmentId, adminId) => {
    try {
        console.log(`💰 Adding immediate interest for investment ${investmentId}`);
        
        const investment = await Investment.findById(investmentId)
            .populate('plan', 'daily_interest name')
            .populate('user');
        
        if (!investment) {
            throw new Error('Investment not found');
        }
        
        if (investment.immediate_interest_added) {
            console.log('⚠️ Immediate interest already added for this investment');
            return { success: false, message: 'Immediate interest already added' };
        }
        
        const dailyEarning = (investment.amount * investment.plan.daily_interest) / 100;
        
        // Update investment with immediate interest
        investment.earned_so_far = dailyEarning;
        investment.immediate_interest_added = true;
        investment.immediate_interest_amount = dailyEarning;
        investment.interest_added_count = 1;
        investment.last_earning_date = new Date();
        investment.next_interest_date = new Date(Date.now() + 24 * 60 * 60 * 1000);
        
        // Calculate remaining days
        const timeRemaining = investment.end_date - new Date();
        const daysRemaining = Math.ceil(timeRemaining / (1000 * 60 * 60 * 24));
        investment.remaining_days = Math.max(0, daysRemaining);
        
        await investment.save();
        
        // Credit user's earnings immediately
        await createTransaction(
            investment.user._id,
            'daily_interest',
            dailyEarning,
            `Immediate interest after approval from ${investment.plan.name} investment`,
            'completed',
            {
                investment_id: investment._id,
                plan_name: investment.plan.name,
                daily_interest_rate: investment.plan.daily_interest,
                investment_amount: investment.amount,
                immediate_interest: true,
                approved_by_admin: adminId
            }
        );
        
        await createNotification(
            investment.user._id,
            'Immediate Interest Added!',
            `Your investment in ${investment.plan.name} has been approved. First interest of ₦${dailyEarning.toLocaleString()} has been credited immediately! Next interest in 24 hours.`,
            'success',
            '/investments'
        );
        
        console.log(`✅ Immediate interest added: ₦${dailyEarning.toLocaleString()} for investment ${investmentId}`);
        
        return {
            success: true,
            immediateInterest: dailyEarning,
            nextInterestDate: investment.next_interest_date
        };
        
    } catch (error) {
        console.error('❌ Error adding immediate interest:', error);
        throw error;
    }
};

// ==================== REFERRAL COMMISSION FUNCTION ====================
const awardReferralCommission = async (referredUserId, investmentAmount, investmentId) => {
    try {
        console.log(`🎯 Checking referral commission for user ${referredUserId}, investment: ₦${investmentAmount}`);
        
        const referredUser = await User.findById(referredUserId);
        if (!referredUser || !referredUser.referred_by) {
            console.log('❌ No referrer found for this user');
            return { success: false, message: 'No referrer found' };
        }
        
        // Check if this is the user's first investment
        const userInvestments = await Investment.countDocuments({
            user: referredUserId,
            status: { $in: ['active', 'completed'] }
        });
        
        if (userInvestments > 1) {
            console.log('⚠️ Not first investment, skipping referral commission');
            return { success: false, message: 'Not first investment' };
        }
        
        // Check if referral commission was already paid
        const referral = await Referral.findOne({
            referred_user: referredUserId,
            referrer: referredUser.referred_by,
            first_investment_commission_paid: false
        });
        
        if (!referral) {
            console.log('⚠️ Referral commission already paid or referral not found');
            return { success: false, message: 'Commission already paid or referral not found' };
        }
        
        // Calculate commission (percentage of first investment)
        const commission = investmentAmount * (config.referralCommissionPercent / 100);
        
        // Award commission to referrer
        await createTransaction(
            referredUser.referred_by,
            'referral_bonus',
            commission,
            `Referral commission from ${referredUser.full_name}'s first investment`,
            'completed',
            {
                referred_user_id: referredUserId,
                investment_id: investmentId,
                commission_percentage: config.referralCommissionPercent,
                first_investment_amount: investmentAmount
            }
        );
        
        // Update referral record
        referral.total_commission = commission;
        referral.first_investment_commission_paid = true;
        referral.first_investment_amount = investmentAmount;
        referral.first_investment_date = new Date();
        referral.earnings_paid = true;
        referral.paid_at = new Date();
        referral.status = 'completed';
        await referral.save();
        
        // Update referrer's user record
        const referrer = await User.findById(referredUser.referred_by);
        if (referrer) {
            referrer.referral_earnings = (referrer.referral_earnings || 0) + commission;
            referrer.withdrawable_earnings = (referrer.withdrawable_earnings || 0) + commission;
            referrer.balance = (referrer.balance || 0) + commission;
            await referrer.save();
        }
        
        await createNotification(
            referredUser.referred_by,
            'Referral Commission Earned!',
            `You earned ₦${commission.toLocaleString()} commission from ${referredUser.full_name}'s first investment.`,
            'referral',
            '/referrals'
        );
        
        console.log(`✅ Referral commission awarded: ₦${commission.toLocaleString()} to user ${referredUser.referred_by}`);
        
        return {
            success: true,
            commission,
            referrerId: referredUser.referred_by,
            referredUserId: referredUserId
        };
    } catch (error) {
        console.error('❌ Error awarding referral commission:', error);
        return {
            success: false,
            error: error.message
        };
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
        
        if (user.account_status !== 'active') {
            return res.status(401).json(formatResponse(false, `Account is ${user.account_status}. Please contact support.`));
        }
        
        // Update last active time
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
        await createAdminUser();
        await createEnhancedInvestmentPlans();
        console.log('✅ Database initialization completed');
    } catch (error) {
        console.error('❌ Database initialization error:', error.message);
        throw error;
    }
};

// ==================== ENHANCED INVESTMENT PLANS WITH UPDATED INTEREST RATES ====================
const createEnhancedInvestmentPlans = async () => {
    // Calculate interest rates based on configuration
    const calculateInterestRate = (baseRate, tier) => {
        return baseRate + (tier * config.interestRateIncrement);
    };
    
    const enhancedPlans = [
        // Base plan: 3500 gets 15%
        {
            name: 'Cocoa Beans',
            description: 'Invest in premium cocoa beans with enhanced returns.',
            min_amount: 3500,
            max_amount: 50000,
            daily_interest: calculateInterestRate(config.baseInterestRate, 0), // 15%
            total_interest: calculateInterestRate(config.baseInterestRate, 0) * 30, // 450%
            duration: 30,
            risk_level: 'low',
            raw_material: 'Cocoa',
            category: 'agriculture',
            is_popular: true,
            features: ['Low Risk', 'Enhanced Returns', 'Beginner Friendly', 'Daily Payouts', 'Immediate Interest'],
            color: '#10b981',
            icon: '🌱',
            display_order: 1
        },
        // Tier 1: +5% = 20%
        {
            name: 'Gold',
            description: 'Precious metal investment with premium returns.',
            min_amount: 50000,
            max_amount: 500000,
            daily_interest: calculateInterestRate(config.baseInterestRate, 1), // 20%
            total_interest: calculateInterestRate(config.baseInterestRate, 1) * 30, // 600%
            duration: 30,
            risk_level: 'medium',
            raw_material: 'Gold',
            category: 'metals',
            is_popular: true,
            features: ['Medium Risk', 'Premium Returns', 'High Liquidity', 'Market Stability', 'Enhanced Earnings'],
            color: '#fbbf24',
            icon: '🥇',
            display_order: 2
        },
        // Tier 2: +10% = 25%
        {
            name: 'Crude Oil',
            description: 'Energy sector investment with maximum returns.',
            min_amount: 100000,
            max_amount: 1000000,
            daily_interest: calculateInterestRate(config.baseInterestRate, 2), // 25%
            total_interest: calculateInterestRate(config.baseInterestRate, 2) * 30, // 750%
            duration: 30,
            risk_level: 'high',
            raw_material: 'Crude Oil',
            category: 'energy',
            is_popular: true,
            features: ['High Risk', 'Maximum Returns', 'Premium Investment', 'Energy Sector', 'Enhanced Payouts'],
            color: '#dc2626',
            icon: '🛢️',
            display_order: 3
        },
        // Tier 1 for new plans: +5% = 20%
        {
            name: 'Coffee Beans',
            description: 'Premium Arabica coffee beans with enhanced returns.',
            min_amount: 5500,
            max_amount: 25000,
            daily_interest: calculateInterestRate(config.baseInterestRate, 1), // 20%
            total_interest: calculateInterestRate(config.baseInterestRate, 1) * 30, // 600%
            duration: 30,
            risk_level: 'low',
            raw_material: 'Coffee',
            category: 'agriculture',
            is_popular: false,
            features: ['Very Low Risk', 'Enhanced Returns', 'Global Demand', 'Daily Payouts', 'Stable Growth'],
            color: '#8B4513',
            icon: '☕',
            display_order: 4
        },
        // Tier 2: +10% = 25%
        {
            name: 'Silver Bullion',
            description: 'Industrial silver with premium technology returns.',
            min_amount: 15000,
            max_amount: 150000,
            daily_interest: calculateInterestRate(config.baseInterestRate, 2), // 25%
            total_interest: calculateInterestRate(config.baseInterestRate, 2) * 30, // 750%
            duration: 30,
            risk_level: 'medium',
            raw_material: 'Silver',
            category: 'metals',
            is_popular: false,
            features: ['Medium Risk', 'Premium Returns', 'Industrial Demand', 'Portfolio Diversification'],
            color: '#C0C0C0',
            icon: '🥈',
            display_order: 5
        },
        // Tier 3: +15% = 30%
        {
            name: 'Timber (Teak)',
            description: 'Premium Teak wood with maximum value returns.',
            min_amount: 20000,
            max_amount: 200000,
            daily_interest: calculateInterestRate(config.baseInterestRate, 3), // 30%
            total_interest: calculateInterestRate(config.baseInterestRate, 3) * 30, // 900%
            duration: 30,
            risk_level: 'medium',
            raw_material: 'Teak Wood',
            category: 'timber',
            is_popular: false,
            features: ['Sustainable', 'Maximum Returns', 'High Demand', 'Long-term Value'],
            color: '#8B4513',
            icon: '🌳',
            display_order: 6
        },
        // Tier 4: +20% = 35%
        {
            name: 'Natural Gas',
            description: 'Clean energy source with premium enhanced returns.',
            min_amount: 75000,
            max_amount: 750000,
            daily_interest: calculateInterestRate(config.baseInterestRate, 4), // 35%
            total_interest: calculateInterestRate(config.baseInterestRate, 4) * 30, // 1050%
            duration: 30,
            risk_level: 'high',
            raw_material: 'Natural Gas',
            category: 'energy',
            is_popular: false,
            features: ['Maximum Returns', 'Energy Transition', 'Global Market', 'Premium Investment'],
            color: '#4169E1',
            icon: '🔥',
            display_order: 7
        },
        // Tier 3: +15% = 30%
        {
            name: 'Aquaculture (Salmon)',
            description: 'Premium salmon farming with enhanced sustainable returns.',
            min_amount: 30000,
            max_amount: 300000,
            daily_interest: calculateInterestRate(config.baseInterestRate, 3), // 30%
            total_interest: calculateInterestRate(config.baseInterestRate, 3) * 30, // 900%
            duration: 30,
            risk_level: 'medium',
            raw_material: 'Salmon',
            category: 'aquaculture',
            is_popular: false,
            features: ['Sustainable Farming', 'Enhanced Returns', 'Growing Demand', 'Regular Payouts'],
            color: '#FF6B6B',
            icon: '🐟',
            display_order: 8
        }
    ];
    
    try {
        for (const planData of enhancedPlans) {
            const existingPlan = await InvestmentPlan.findOne({ name: planData.name });
            if (!existingPlan) {
                await InvestmentPlan.create(planData);
                console.log(`✅ Created investment plan: ${planData.name} (${planData.daily_interest}% daily)`);
            } else {
                // Update existing plan with enhanced data
                await InvestmentPlan.findByIdAndUpdate(existingPlan._id, planData);
                console.log(`✅ Updated investment plan: ${planData.name} (${planData.daily_interest}% daily)`);
            }
        }
        
        const totalPlans = await InvestmentPlan.countDocuments();
        console.log(`✅ Enhanced investment plans created/verified: ${totalPlans} plans`);
        console.log(`💰 Enhanced price range: ₦${enhancedPlans.reduce((min, plan) => Math.min(min, plan.min_amount), Infinity).toLocaleString()} - ₦${enhancedPlans.reduce((max, plan) => Math.max(max, plan.max_amount || plan.min_amount), 0).toLocaleString()}`);
        console.log(`📈 Enhanced interest range: ${enhancedPlans.reduce((min, plan) => Math.min(min, plan.daily_interest), Infinity)}% - ${enhancedPlans.reduce((max, plan) => Math.max(max, plan.daily_interest), 0)}% daily`);
        
    } catch (error) {
        console.error('Error creating enhanced investment plans:', error);
    }
};

const createAdminUser = async () => {
    try {
        const adminEmail = process.env.ADMIN_EMAIL || 'admin@rawwealthy.com';
        const adminPassword = process.env.ADMIN_PASSWORD || 'Admin123456';
        
        let existingAdmin = await User.findOne({ email: adminEmail });
        if (existingAdmin) {
            console.log('✅ Admin already exists in database');
            
            if (existingAdmin.role !== 'super_admin') {
                existingAdmin.role = 'super_admin';
                await existingAdmin.save();
                console.log('✅ Admin role updated to super_admin');
            }
            return;
        }
        
        const admin = new User({
            full_name: 'Raw Wealthy Admin',
            email: adminEmail,
            phone: '09161806424',
            password: adminPassword,
            role: 'super_admin',
            balance: 1000000,
            total_earnings: 500000,
            referral_earnings: 200000,
            withdrawable_earnings: 700000,
            kyc_verified: true,
            kyc_status: 'verified',
            is_active: true,
            is_verified: true,
            email_notifications: true,
            total_deposits: 2000000,
            total_withdrawals: 500000,
            total_investments: 1500000,
            account_status: 'active'
        });
        
        await admin.save();
        console.log('✅ Admin created successfully');
        
        await createNotification(
            admin._id,
            'Welcome Admin!',
            'Your admin account has been successfully created with enhanced privileges.',
            'success',
            '/admin/dashboard'
        );
        
        console.log('\n🎉 =========== ENHANCED ADMIN SETUP COMPLETED ===========');
        console.log(`📧 Login Email: ${adminEmail}`);
        console.log(`🔑 Login Password: ${adminPassword}`);
        console.log(`👉 Login at: ${config.clientURL}/admin/login`);
        console.log('=====================================================\n');
        
    } catch (error) {
        console.error('Admin creation error:', error);
    }
};

// ==================== HEALTH CHECK ====================
app.get('/health', async (req, res) => {
    const health = {
        success: true,
        status: 'OK',
        timestamp: new Date().toISOString(),
        version: '51.0.0',
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
            withdrawals: await Withdrawal.countDocuments({}),
            plans: await InvestmentPlan.countDocuments({})
        }
    };
    
    res.json(health);
});

// ==================== ROOT ENDPOINT ====================
app.get('/', (req, res) => {
    res.json({
        success: true,
        message: '🚀 Raw Wealthy Backend API v51.0 - Enhanced Production Ready',
        version: '51.0.0',
        timestamp: new Date().toISOString(),
        status: 'Operational',
        environment: config.nodeEnv,
        features: {
            immediate_interest: 'Enabled - Interest added immediately after admin approval',
            daily_interest: 'Every 24 hours until expiry',
            interest_rates: 'Enhanced: 15% base +5% increments',
            admin_controls: 'Full user management with rejection capability',
            withdrawal_approval: 'All withdrawals require admin approval'
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
            forgot_password: '/api/auth/forgot-password',
            health: '/health'
        }
    });
});

// ==================== ENHANCED DEBUGGING ENDPOINTS ====================
app.get('/api/debug/earnings-status/:userId', auth, async (req, res) => {
    try {
        const userId = req.params.userId;
        
        // Check if authorized
        if (req.user.role !== 'admin' && req.user._id.toString() !== userId) {
            return res.status(403).json(formatResponse(false, 'Unauthorized access'));
        }
        
        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json(formatResponse(false, 'User not found'));
        }
        
        const transactions = await Transaction.find({ user: userId })
            .sort({ createdAt: -1 })
            .limit(20);
        
        const investments = await Investment.find({ user: userId })
            .populate('plan', 'name daily_interest');
        
        // Calculate earnings from transactions
        let calculatedTotalEarnings = 0;
        let calculatedReferralEarnings = 0;
        let calculatedWithdrawn = 0;
        
        transactions.forEach(t => {
            if (t.status === 'completed') {
                if (t.type === 'daily_interest' && t.amount > 0) {
                    calculatedTotalEarnings += t.amount;
                } else if (t.type === 'referral_bonus' && t.amount > 0) {
                    calculatedReferralEarnings += t.amount;
                } else if (t.type === 'withdrawal' && t.amount < 0) {
                    calculatedWithdrawn += Math.abs(t.amount);
                }
            }
        });
        
        const calculatedWithdrawable = Math.max(0, 
            calculatedTotalEarnings + calculatedReferralEarnings - calculatedWithdrawn
        );
        
        res.json({
            success: true,
            user: {
                email: user.email,
                stored: {
                    balance: user.balance,
                    total_earnings: user.total_earnings,
                    referral_earnings: user.referral_earnings,
                    withdrawable_earnings: user.withdrawable_earnings,
                    total_withdrawn: user.total_withdrawn
                },
                calculated: {
                    total_earnings: calculatedTotalEarnings,
                    referral_earnings: calculatedReferralEarnings,
                    total_withdrawn: calculatedWithdrawn,
                    withdrawable_earnings: calculatedWithdrawable
                },
                discrepancies: {
                    total_earnings: Math.abs(user.total_earnings - calculatedTotalEarnings),
                    referral_earnings: Math.abs(user.referral_earnings - calculatedReferralEarnings),
                    withdrawable_earnings: Math.abs(user.withdrawable_earnings - calculatedWithdrawable)
                }
            },
            transactions: {
                count: transactions.length,
                daily_interest: transactions.filter(t => t.type === 'daily_interest').length,
                referral_bonus: transactions.filter(t => t.type === 'referral_bonus').length,
                withdrawal: transactions.filter(t => t.type === 'withdrawal').length,
                recent: transactions.slice(0, 5).map(t => ({
                    type: t.type,
                    amount: t.amount,
                    description: t.description,
                    createdAt: t.createdAt
                }))
            },
            investments: {
                count: investments.length,
                active: investments.filter(i => i.status === 'active').length,
                total_invested: investments.reduce((sum, i) => sum + i.amount, 0),
                total_earned: investments.reduce((sum, i) => sum + (i.earned_so_far || 0), 0),
                immediate_interests: investments.filter(i => i.immediate_interest_added).length,
                list: investments.map(i => ({
                    plan: i.plan?.name,
                    amount: i.amount,
                    earned_so_far: i.earned_so_far,
                    immediate_interest_added: i.immediate_interest_added,
                    status: i.status,
                    next_interest_date: i.next_interest_date,
                    interest_added_count: i.interest_added_count,
                    remaining_days: i.remaining_days
                }))
            }
        });
    } catch (error) {
        console.error('Earnings status error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// ==================== AUTH ENDPOINTS ====================
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
            referred_by: referredBy ? referredBy._id : null,
            total_earnings: 0,
            referral_earnings: 0,
            withdrawable_earnings: 0,
            total_deposits: 0,
            total_withdrawals: 0,
            total_investments: 0,
            account_status: 'active'
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
        
        if (config.emailEnabled) {
            await sendEmail(
                user.email,
                'Welcome to Raw Wealthy!',
                `<h2>Welcome ${user.full_name}!</h2>
                <p>Your account has been successfully created.</p>
                <p><strong>Account Details:</strong></p>
                <ul>
                    <li>Email: ${user.email}</li>
                    <li>Balance: ₦${user.balance.toLocaleString()}</li>
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
        
        if (!user.is_active) {
            return res.status(401).json(formatResponse(false, 'Account is deactivated. Please contact support.'));
        }
        
        if (user.account_status !== 'active') {
            return res.status(401).json(formatResponse(false, `Account is ${user.account_status}. Please contact support.`));
        }
        
        const isMatch = await user.comparePassword(password);
        if (!isMatch) {
            return res.status(400).json(formatResponse(false, 'Invalid credentials'));
        }
        
        user.last_login = new Date();
        user.last_active = new Date();
        
        // Track login location
        user.login_history.push({
            ip: req.ip,
            location: req.headers['x-forwarded-for'] || req.connection.remoteAddress,
            device: req.headers['user-agent'],
            timestamp: new Date()
        });
        
        // Keep only last 10 login records
        if (user.login_history.length > 10) {
            user.login_history = user.login_history.slice(-10);
        }
        
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

// ==================== PROFILE ENDPOINTS ====================
app.get('/api/profile', auth, async (req, res) => {
    try {
        const userId = req.user._id;
        const user = await User.findById(userId)
            .select('-password -two_factor_secret -verification_token -password_reset_token');
        
        if (!user) {
            return res.status(404).json(formatResponse(false, 'User not found'));
        }
        
        const userData = user.toObject();
        
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
                balance: userData.balance || 0,
                total_earnings: userData.total_earnings || 0,
                referral_earnings: userData.referral_earnings || 0,
                withdrawable_earnings: userData.withdrawable_earnings || 0,
                available_for_withdrawal: userData.available_for_withdrawal || 0,
                daily_interest: dailyInterest,
                
                total_investments: investments,
                active_investments: activeInvestments.length,
                total_deposits: deposits,
                total_withdrawals: withdrawals,
                referral_count: referrals,
                active_investment_value: activeInvestmentValue,
                portfolio_value: userData.portfolio_value
            }
        };
        
        res.json(formatResponse(true, 'Profile retrieved successfully', profileData));
    } catch (error) {
        console.error('Error fetching profile:', error);
        handleError(res, error, 'Error fetching profile');
    }
});

// ==================== INVESTMENT PLANS ENDPOINTS - ENHANCED INTEREST RATES ====================
app.get('/api/plans', async (req, res) => {
    try {
        const plans = await InvestmentPlan.find({ is_active: true })
            .sort({ display_order: 1, min_amount: 1 })
            .lean();
        
        // Categorize plans by risk level and price range
        const categorizedPlans = {
            beginner: plans.filter(p => p.min_amount <= 10000 && p.risk_level === 'low'),
            intermediate: plans.filter(p => p.min_amount > 10000 && p.min_amount <= 50000 && p.risk_level === 'medium'),
            advanced: plans.filter(p => p.min_amount > 50000 && p.risk_level === 'high'),
            popular: plans.filter(p => p.is_popular === true),
            enhanced_returns: plans.filter(p => p.daily_interest >= 25) // Highlight high-interest plans
        };
        
        res.json(formatResponse(true, 'Enhanced plans retrieved successfully', { 
            plans,
            categorized: categorizedPlans,
            summary: {
                total_plans: plans.length,
                low_risk: plans.filter(p => p.risk_level === 'low').length,
                medium_risk: plans.filter(p => p.risk_level === 'medium').length,
                high_risk: plans.filter(p => p.risk_level === 'high').length,
                enhanced_interest: plans.filter(p => p.daily_interest >= 25).length,
                price_range: {
                    min: plans.reduce((min, plan) => Math.min(min, plan.min_amount), Infinity),
                    max: plans.reduce((max, plan) => Math.max(max, plan.max_amount || plan.min_amount), 0)
                },
                interest_range: {
                    min: plans.reduce((min, plan) => Math.min(min, plan.daily_interest), Infinity),
                    max: plans.reduce((max, plan) => Math.max(max, plan.daily_interest), 0)
                }
            }
        }));
    } catch (error) {
        handleError(res, error, 'Error fetching investment plans');
    }
});

// ==================== ENHANCED INVESTMENT ENDPOINTS WITH IMMEDIATE INTEREST ====================
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
        
        const freshUser = await User.findById(userId);
        if (!freshUser) {
            return res.status(404).json(formatResponse(false, 'User not found'));
        }
        
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
        
        if (investmentAmount > freshUser.balance) {
            return res.status(400).json(formatResponse(false, 'Insufficient balance for this investment'));
        }
        
        let proofUrl = null;
        if (req.file) {
            try {
                const uploadResult = await handleFileUpload(req.file, 'investment-proofs', userId);
                proofUrl = uploadResult.url;
            } catch (uploadError) {
                return res.status(400).json(formatResponse(false, `File upload failed: ${uploadError.message}`));
            }
        }
        
        const expectedEarnings = (investmentAmount * plan.total_interest) / 100;
        const dailyEarnings = (investmentAmount * plan.daily_interest) / 100;
        const endDate = new Date(Date.now() + plan.duration * 24 * 60 * 60 * 1000);
        const nextInterestDate = new Date(Date.now() + 24 * 60 * 60 * 1000);
        
        const investment = new Investment({
            user: userId,
            plan: plan_id,
            amount: investmentAmount,
            status: proofUrl ? 'pending' : 'active',
            start_date: new Date(),
            end_date: endDate,
            expected_earnings: expectedEarnings,
            daily_earnings: dailyEarnings,
            next_interest_date: nextInterestDate,
            total_interest_days: plan.duration,
            remaining_days: plan.duration,
            auto_renew,
            payment_proof_url: proofUrl,
            payment_verified: !proofUrl
        });
        
        await investment.save();
        
        // Deduct investment amount from user's balance
        await createTransaction(
            userId,
            'investment',
            -investmentAmount,
            `Investment in ${plan.name} plan (${plan.daily_interest}% daily)`,
            'completed',
            {
                investment_id: investment._id,
                plan_name: plan.name,
                plan_duration: plan.duration,
                daily_interest: plan.daily_interest,
                next_interest_date: nextInterestDate,
                immediate_interest_pending: !proofUrl
            }
        );
        
        await InvestmentPlan.findByIdAndUpdate(plan_id, {
            $inc: {
                investment_count: 1,
                total_invested: investmentAmount
            }
        });
        
        // If auto-approved (no proof required)
        if (!proofUrl) {
            // Add immediate interest
            const immediateInterestResult = await addImmediateInterest(investment._id, 'system');
            
            // Update user's first investment tracking
            const userInvestmentsCount = await Investment.countDocuments({
                user: userId,
                status: { $in: ['active', 'completed'] }
            });
            
            if (userInvestmentsCount === 1) { // This is the first investment
                freshUser.first_investment_amount = investmentAmount;
                freshUser.first_investment_date = new Date();
                await freshUser.save();
            }
            
            // Award referral commission for first investment
            if (config.referralCommissionOnFirstInvestment && freshUser.referred_by && userInvestmentsCount === 1) {
                await awardReferralCommission(userId, investmentAmount, investment._id);
            }
        } else {
            await createNotification(
                userId,
                'Investment Created',
                `Your investment of ₦${investmentAmount.toLocaleString()} in ${plan.name} has been created and is pending admin approval.`,
                'investment',
                '/investments'
            );
        }
        
        res.status(201).json(formatResponse(true, 'Investment created successfully!', {
            investment: {
                ...investment.toObject(),
                plan_name: plan.name,
                expected_daily_earnings: dailyEarnings,
                expected_total_earnings: expectedEarnings,
                end_date: endDate,
                next_interest_date: nextInterestDate,
                immediate_interest_added: !proofUrl
            }
        }));
    } catch (error) {
        handleError(res, error, 'Error creating investment');
    }
});

// ==================== ENHANCED ADMIN ENDPOINTS - WITH USER REJECTION CAPABILITY ====================
app.post('/api/admin/users/:id/suspend', adminAuth, [
    body('reason').notEmpty().trim(),
    body('duration_days').optional().isInt({ min: 1 })
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json(formatResponse(false, 'Validation failed'));
        }
        
        const userId = req.params.id;
        const adminId = req.user._id;
        const { reason, duration_days } = req.body;
        
        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json(formatResponse(false, 'User not found'));
        }
        
        // Cannot suspend admins
        if (user.role === 'admin' || user.role === 'super_admin') {
            return res.status(403).json(formatResponse(false, 'Cannot suspend admin users'));
        }
        
        // Calculate suspension end date
        let suspensionEndDate = null;
        if (duration_days) {
            suspensionEndDate = new Date();
            suspensionEndDate.setDate(suspensionEndDate.getDate() + parseInt(duration_days));
        }
        
        user.account_status = 'suspended';
        user.suspension_reason = reason;
        user.suspension_end_date = suspensionEndDate;
        user.is_active = false;
        
        await user.save();
        
        // Create audit log
        const auditLog = new AdminAudit({
            admin_id: adminId,
            action: 'suspend_user',
            target_type: 'user',
            target_id: userId,
            details: {
                reason,
                duration_days,
                suspension_end_date: suspensionEndDate,
                previous_status: 'active'
            },
            ip_address: req.ip,
            user_agent: req.headers['user-agent']
        });
        
        await auditLog.save();
        
        await createNotification(
            userId,
            'Account Suspended',
            `Your account has been suspended. Reason: ${reason}${duration_days ? ` for ${duration_days} days` : ''}.`,
            'error',
            '/profile'
        );
        
        // Notify admins
        emitToUserManagement('user-suspended', {
            user_id: userId,
            user_name: user.full_name,
            admin_id: adminId,
            admin_name: req.user.full_name,
            reason,
            duration_days,
            suspension_end_date: suspensionEndDate
        });
        
        res.json(formatResponse(true, 'User suspended successfully', {
            user: {
                id: user._id,
                email: user.email,
                full_name: user.full_name,
                account_status: user.account_status,
                suspension_reason: user.suspension_reason,
                suspension_end_date: user.suspension_end_date
            }
        }));
    } catch (error) {
        handleError(res, error, 'Error suspending user');
    }
});

app.post('/api/admin/users/:id/ban', adminAuth, [
    body('reason').notEmpty().trim()
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json(formatResponse(false, 'Validation failed'));
        }
        
        const userId = req.params.id;
        const adminId = req.user._id;
        const { reason } = req.body;
        
        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json(formatResponse(false, 'User not found'));
        }
        
        // Cannot ban admins
        if (user.role === 'admin' || user.role === 'super_admin') {
            return res.status(403).json(formatResponse(false, 'Cannot ban admin users'));
        }
        
        user.account_status = 'banned';
        user.suspension_reason = reason;
        user.banned_by = adminId;
        user.banned_at = new Date();
        user.is_active = false;
        
        await user.save();
        
        // Create audit log
        const auditLog = new AdminAudit({
            admin_id: adminId,
            action: 'ban_user',
            target_type: 'user',
            target_id: userId,
            details: {
                reason,
                previous_status: user.account_status
            },
            ip_address: req.ip,
            user_agent: req.headers['user-agent']
        });
        
        await auditLog.save();
        
        await createNotification(
            userId,
            'Account Banned',
            `Your account has been permanently banned. Reason: ${reason}.`,
            'error',
            '/contact'
        );
        
        // Notify admins
        emitToUserManagement('user-banned', {
            user_id: userId,
            user_name: user.full_name,
            admin_id: adminId,
            admin_name: req.user.full_name,
            reason,
            banned_at: user.banned_at
        });
        
        res.json(formatResponse(true, 'User banned successfully', {
            user: {
                id: user._id,
                email: user.email,
                full_name: user.full_name,
                account_status: user.account_status,
                suspension_reason: user.suspension_reason,
                banned_by: user.banned_by,
                banned_at: user.banned_at
            }
        }));
    } catch (error) {
        handleError(res, error, 'Error banning user');
    }
});

app.post('/api/admin/users/:id/activate', adminAuth, async (req, res) => {
    try {
        const userId = req.params.id;
        const adminId = req.user._id;
        
        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json(formatResponse(false, 'User not found'));
        }
        
        user.account_status = 'active';
        user.suspension_reason = null;
        user.suspension_end_date = null;
        user.banned_by = null;
        user.banned_at = null;
        user.is_active = true;
        
        await user.save();
        
        // Create audit log
        const auditLog = new AdminAudit({
            admin_id: adminId,
            action: 'activate_user',
            target_type: 'user',
            target_id: userId,
            details: {
                previous_status: user.account_status
            },
            ip_address: req.ip,
            user_agent: req.headers['user-agent']
        });
        
        await auditLog.save();
        
        await createNotification(
            userId,
            'Account Reactivated',
            'Your account has been reactivated and you can now use the platform.',
            'success',
            '/dashboard'
        );
        
        // Notify admins
        emitToUserManagement('user-activated', {
            user_id: userId,
            user_name: user.full_name,
            admin_id: adminId,
            admin_name: req.user.full_name
        });
        
        res.json(formatResponse(true, 'User activated successfully', {
            user: {
                id: user._id,
                email: user.email,
                full_name: user.full_name,
                account_status: user.account_status
            }
        }));
    } catch (error) {
        handleError(res, error, 'Error activating user');
    }
});

// ==================== ENHANCED INVESTMENT APPROVAL WITH IMMEDIATE INTEREST ====================
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
        
        // Add immediate interest
        const immediateInterestResult = await addImmediateInterest(investmentId, adminId);
        
        // Update investment status
        investment.status = 'active';
        investment.approved_at = new Date();
        investment.approved_by = adminId;
        investment.payment_verified = true;
        investment.remarks = remarks;
        
        await investment.save();
        
        // Check if this is the user's first investment
        const userInvestmentsCount = await Investment.countDocuments({
            user: investment.user._id,
            status: { $in: ['active', 'completed'] }
        });
        
        if (userInvestmentsCount === 1) { // This is the first investment
            await User.findByIdAndUpdate(investment.user._id, {
                first_investment_amount: investment.amount,
                first_investment_date: new Date()
            });
            
            // Award referral commission for first investment
            if (config.referralCommissionOnFirstInvestment) {
                await awardReferralCommission(investment.user._id, investment.amount, investment._id);
            }
        }
        
        // Create audit log
        const auditLog = new AdminAudit({
            admin_id: adminId,
            action: 'approve_investment',
            target_type: 'investment',
            target_id: investmentId,
            details: {
                amount: investment.amount,
                plan_name: investment.plan.name,
                daily_interest: investment.plan.daily_interest,
                immediate_interest_added: true,
                immediate_interest_amount: immediateInterestResult.immediateInterest
            },
            ip_address: req.ip,
            user_agent: req.headers['user-agent']
        });
        
        await auditLog.save();
        
        res.json(formatResponse(true, 'Investment approved with immediate interest!', {
            investment: investment.toObject(),
            immediate_interest: {
                added: true,
                amount: immediateInterestResult.immediateInterest,
                next_interest_date: immediateInterestResult.nextInterestDate
            }
        }));
    } catch (error) {
        handleError(res, error, 'Error approving investment');
    }
});

// ==================== ENHANCED WITHDRAWAL REJECTION ENDPOINT ====================
app.post('/api/admin/withdrawals/:id/reject', adminAuth, [
    body('rejection_reason').notEmpty().trim()
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json(formatResponse(false, 'Validation failed'));
        }
        
        const withdrawalId = req.params.id;
        const adminId = req.user._id;
        const { rejection_reason } = req.body;
        
        const withdrawal = await Withdrawal.findById(withdrawalId)
            .populate('user');
        
        if (!withdrawal) {
            return res.status(404).json(formatResponse(false, 'Withdrawal not found'));
        }
        
        if (withdrawal.status !== 'pending') {
            return res.status(400).json(formatResponse(false, 'Withdrawal is not pending'));
        }
        
        withdrawal.status = 'rejected';
        withdrawal.admin_review_status = 'rejected';
        withdrawal.reviewed_by = adminId;
        withdrawal.review_date = new Date();
        withdrawal.review_notes = rejection_reason;
        withdrawal.rejection_reason = rejection_reason;
        withdrawal.rejected_by = adminId;
        withdrawal.rejected_at = new Date();
        
        await withdrawal.save();
        
        // Create audit log
        const auditLog = new AdminAudit({
            admin_id: adminId,
            action: 'reject_withdrawal',
            target_type: 'withdrawal',
            target_id: withdrawalId,
            details: {
                amount: withdrawal.amount,
                payment_method: withdrawal.payment_method,
                rejection_reason
            },
            ip_address: req.ip,
            user_agent: req.headers['user-agent']
        });
        
        await auditLog.save();
        
        // Update the pending transaction to failed
        await Transaction.findOneAndUpdate(
            { related_withdrawal: withdrawalId, status: 'pending' },
            {
                status: 'cancelled',
                description: `Withdrawal rejected: ${rejection_reason}`
            }
        );
        
        await createNotification(
            withdrawal.user._id,
            'Withdrawal Rejected',
            `Your withdrawal request of ₦${withdrawal.amount.toLocaleString()} has been rejected. Reason: ${rejection_reason}`,
            'error',
            '/withdrawals'
        );
        
        res.json(formatResponse(true, 'Withdrawal rejected successfully', {
            withdrawal: withdrawal.toObject()
        }));
    } catch (error) {
        handleError(res, error, 'Error rejecting withdrawal');
    }
});

// ==================== ENHANCED ADMIN DASHBOARD ====================
app.get('/api/admin/dashboard', adminAuth, async (req, res) => {
    try {
        const [
            totalUsers,
            activeUsers,
            suspendedUsers,
            bannedUsers,
            newUsersToday,
            newUsersWeek,
            totalInvestments,
            activeInvestments,
            totalDeposits,
            totalWithdrawals,
            pendingInvestments,
            pendingDeposits,
            pendingWithdrawals,
            pendingKYC,
            amlFlags
        ] = await Promise.all([
            User.countDocuments({}),
            User.countDocuments({ account_status: 'active' }),
            User.countDocuments({ account_status: 'suspended' }),
            User.countDocuments({ account_status: 'banned' }),
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
            KYCSubmission.countDocuments({ status: 'pending' }),
            AmlMonitoring.countDocuments({ status: 'pending_review' })
        ]);
        
        const earningsResult = await Investment.aggregate([
            { $match: { status: 'active' } },
            { $group: { _id: null, total: { $sum: '$earned_so_far' } } }
        ]);
        
        const totalEarnings = earningsResult[0]?.total || 0;
        
        // Enhanced user financial aggregation
        const userFinancials = await User.aggregate([
            { $match: { role: { $ne: 'super_admin' } } },
            { $group: {
                _id: null,
                total_balance: { $sum: '$balance' },
                total_earnings: { $sum: '$total_earnings' },
                total_referral_earnings: { $sum: '$referral_earnings' },
                total_withdrawn: { $sum: '$total_withdrawn' },
                total_deposits: { $sum: '$total_deposits' },
                total_withdrawals: { $sum: '$total_withdrawals' },
                total_investments: { $sum: '$total_investments' }
            } }
        ]);
        
        const financialSummary = userFinancials[0] || {
            total_balance: 0,
            total_earnings: 0,
            total_referral_earnings: 0,
            total_withdrawn: 0,
            total_deposits: 0,
            total_withdrawals: 0,
            total_investments: 0
        };
        
        const totalPortfolio = (financialSummary.total_balance || 0) +
                              (financialSummary.total_earnings || 0) +
                              (financialSummary.total_referral_earnings || 0);
        
        const stats = {
            overview: {
                total_users: totalUsers,
                active_users: activeUsers,
                suspended_users: suspendedUsers,
                banned_users: bannedUsers,
                new_users_today: newUsersToday,
                new_users_week: newUsersWeek,
                total_investments: totalInvestments,
                active_investments: activeInvestments,
                total_deposits: totalDeposits,
                total_withdrawals: totalWithdrawals,
                total_earnings: totalEarnings,
                total_portfolio_value: totalPortfolio
            },
            user_financials: {
                total_user_balance: financialSummary.total_balance,
                total_user_earnings: financialSummary.total_earnings,
                total_user_referral_earnings: financialSummary.total_referral_earnings,
                total_user_withdrawn: financialSummary.total_withdrawn,
                total_user_deposits: financialSummary.total_deposits,
                total_user_withdrawals: financialSummary.total_withdrawals,
                total_user_investments: financialSummary.total_investments
            },
            pending_actions: {
                pending_investments: pendingInvestments,
                pending_deposits: pendingDeposits,
                pending_withdrawals: pendingWithdrawals,
                pending_kyc: pendingKYC,
                aml_flags: amlFlags,
                total_pending: pendingInvestments + pendingDeposits + pendingWithdrawals + pendingKYC + amlFlags
            }
        };
        
        res.json(formatResponse(true, 'Enhanced admin dashboard stats retrieved successfully', {
            stats,
            quick_links: {
                pending_investments: '/api/admin/pending-investments',
                pending_deposits: '/api/admin/pending-deposits',
                pending_withdrawals: '/api/admin/pending-withdrawals',
                pending_kyc: '/api/admin/pending-kyc',
                aml_flags: '/api/admin/aml-flags',
                all_users: '/api/admin/users',
                suspended_users: '/api/admin/users?status=suspended',
                banned_users: '/api/admin/users?status=banned'
            }
        }));
    } catch (error) {
        handleError(res, error, 'Error fetching admin dashboard stats');
    }
});

// ==================== ENHANCED ADMIN USER MANAGEMENT ====================
app.get('/api/admin/users', adminAuth, async (req, res) => {
    try {
        const {
            page = 1,
            limit = 20,
            status,
            role,
            kyc_status,
            account_status,
            search
        } = req.query;
        
        const query = {};
        
        if (status === 'active') query.is_active = true;
        if (status === 'inactive') query.is_active = false;
        if (role) query.role = role;
        if (kyc_status) query.kyc_status = kyc_status;
        if (account_status) query.account_status = account_status;
        
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
        
        // ENHANCED: Include all financial and status data for admin view
        const enhancedUsers = users.map(user => ({
            ...user,
            portfolio_value: (user.balance || 0),
            available_for_withdrawal: user.withdrawable_earnings || 0,
            financial_summary: {
                balance: user.balance || 0,
                total_earnings: user.total_earnings || 0,
                referral_earnings: user.referral_earnings || 0,
                total_withdrawn: user.total_withdrawn || 0,
                total_deposits: user.total_deposits || 0,
                total_withdrawals: user.total_withdrawals || 0,
                total_investments: user.total_investments || 0
            },
            status_summary: {
                is_active: user.is_active,
                account_status: user.account_status,
                kyc_status: user.kyc_status,
                kyc_verified: user.kyc_verified
            }
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
                active_users: enhancedUsers.filter(u => u.account_status === 'active').length,
                suspended_users: enhancedUsers.filter(u => u.account_status === 'suspended').length,
                banned_users: enhancedUsers.filter(u => u.account_status === 'banned').length,
                verified_users: enhancedUsers.filter(u => u.kyc_verified).length,
                total_balance: enhancedUsers.reduce((sum, u) => sum + (u.balance || 0), 0),
                total_earnings: enhancedUsers.reduce((sum, u) => sum + (u.total_earnings || 0), 0),
                total_referral_earnings: enhancedUsers.reduce((sum, u) => sum + (u.referral_earnings || 0), 0),
                total_withdrawn: enhancedUsers.reduce((sum, u) => sum + (u.total_withdrawn || 0), 0),
                total_withdrawable: enhancedUsers.reduce((sum, u) => sum + (u.withdrawable_earnings || 0), 0)
            }
        }));
    } catch (error) {
        handleError(res, error, 'Error fetching users');
    }
});

// ==================== ENHANCED DAILY INTEREST CRON JOB ====================
// Run every 30 minutes to check for investments needing interest
cron.schedule('*/30 * * * *', async () => {
    console.log('🔄 Running enhanced daily interest calculation...');
    const result = await calculateDailyInterest();
    
    if (result.success) {
        console.log(`✅ Daily interest completed: ${result.investmentsUpdated} investments, ₦${result.totalInterestPaid.toLocaleString()} paid`);
    } else {
        console.error('❌ Daily interest failed:', result.error);
    }
});

// Investment completion check - runs every hour
cron.schedule('0 * * * *', async () => {
    try {
        console.log('🔄 Checking completed investments...');
        
        const completedInvestments = await Investment.find({
            status: 'active',
            end_date: { $lte: new Date() }
        }).populate('user plan');
        
        let investmentsCompleted = 0;
        
        for (const investment of completedInvestments) {
            investment.status = 'completed';
            await investment.save();
            
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

// User suspension expiration check - runs daily
cron.schedule('0 2 * * *', async () => {
    try {
        console.log('🔄 Checking expired user suspensions...');
        
        const now = new Date();
        const expiredSuspensions = await User.find({
            account_status: 'suspended',
            suspension_end_date: { $lte: now, $ne: null }
        });
        
        let suspensionsLifted = 0;
        
        for (const user of expiredSuspensions) {
            user.account_status = 'active';
            user.suspension_reason = null;
            user.suspension_end_date = null;
            user.is_active = true;
            await user.save();
            
            await createNotification(
                user._id,
                'Suspension Lifted',
                'Your account suspension has been lifted. You can now use the platform.',
                'success',
                '/dashboard'
            );
            
            suspensionsLifted++;
        }
        
        console.log(`✅ Suspension expiration check: ${suspensionsLifted} suspensions lifted`);
    } catch (error) {
        console.error('❌ Error in suspension expiration check:', error);
    }
});

// ==================== ERROR HANDLING MIDDLEWARE ====================
app.use((req, res) => {
    res.status(404).json(formatResponse(false, 'Endpoint not found'));
});

app.use((err, req, res, next) => {
    console.error('🚨 Unhandled error:', err);
    
    if (err instanceof multer.MulterError) {
        if (err.code === 'LIMIT_FILE_SIZE') {
            return res.status(400).json(formatResponse(false, 'File too large. Maximum size is 10MB'));
        }
        return res.status(400).json(formatResponse(false, `File upload error: ${err.message}`));
    }
    
    if (err.name === 'ValidationError') {
        const messages = Object.values(err.errors).map(e => e.message);
        return res.status(400).json(formatResponse(false, 'Validation Error', { errors: messages }));
    }
    
    if (err.name === 'JsonWebTokenError') {
        return res.status(401).json(formatResponse(false, 'Invalid token'));
    }
    
    if (err.name === 'TokenExpiredError') {
        return res.status(401).json(formatResponse(false, 'Token expired'));
    }
    
    const statusCode = err.statusCode || 500;
    const message = config.nodeEnv === 'production' && statusCode === 500
        ? 'Internal server error'
        : err.message;
    
    res.status(statusCode).json(formatResponse(false, message));
});

// ==================== START SERVER ====================
const startServer = async () => {
    try {
        await initializeDatabase();
        
        server.listen(config.port, () => {
            console.log('\n🚀 ============================================');
            console.log(`✅ Raw Wealthy Backend v51.0 - ENHANCED PRODUCTION`);
            console.log(`🌐 Environment: ${config.nodeEnv}`);
            console.log(`📍 Port: ${config.port}`);
            console.log(`🔗 Server URL: ${config.serverURL}`);
            console.log(`🔗 Client URL: ${config.clientURL}`);
            console.log(`🔌 Socket.IO: Enabled`);
            console.log(`📊 Database: Connected`);
            console.log('============================================\n');
            
            console.log('🎯 ENHANCED FEATURES ACTIVATED:');
            console.log('1. ✅ IMMEDIATE INTEREST: Added after admin approval');
            console.log('2. ✅ DAILY INTEREST: Every 24 hours until expiry');
            console.log('3. ✅ ENHANCED INTEREST RATES: 15% base +5% increments');
            console.log('4. ✅ ADMIN USER MANAGEMENT: Suspend/Ban/Activate users');
            console.log('5. ✅ WITHDRAWAL REJECTION: Full admin control');
            console.log('6. ✅ ALL WITHDRAWALS REQUIRE ADMIN APPROVAL');
            console.log('7. ✅ ENHANCED INVESTMENT TRACKING: Remaining days');
            console.log('8. ✅ AUTOMATED SUSPENSION LIFTING');
            console.log('============================================\n');
            
            console.log('💰 ENHANCED INTEREST RATES:');
            console.log('1. 🌱 Cocoa Beans: 15% daily (Base rate)');
            console.log('2. 🥇 Gold: 20% daily (+5%)');
            console.log('3. 🛢️ Crude Oil: 25% daily (+10%)');
            console.log('4. ☕ Coffee Beans: 20% daily (+5%)');
            console.log('5. 🥈 Silver Bullion: 25% daily (+10%)');
            console.log('6. 🌳 Timber (Teak): 30% daily (+15%)');
            console.log('7. 🔥 Natural Gas: 35% daily (+20%)');
            console.log('8. 🐟 Aquaculture: 30% daily (+15%)');
            console.log(`📊 Total Investment Plans: 8`);
            console.log(`📈 Interest Range: 15% - 35% daily`);
            console.log(`💰 Price Range: ₦3,500 - ₦1,000,000`);
            console.log('============================================\n');
            
            console.log('👨‍💼 ENHANCED ADMIN CONTROLS:');
            console.log('1. ✅ SUSPEND USER: With reason and duration');
            console.log('2. ✅ BAN USER: Permanent account deactivation');
            console.log('3. ✅ ACTIVATE USER: Reactivate suspended/banned');
            console.log('4. ✅ REJECT WITHDRAWAL: With detailed reason');
            console.log('5. ✅ APPROVE INVESTMENT: With immediate interest');
            console.log('6. ✅ VIEW USER STATUS: Active/Suspended/Banned');
            console.log('============================================\n');
            
            console.log('🔧 ENHANCED AUTOMATION:');
            console.log('• DAILY INTEREST: Every 24 hours automatically');
            console.log('• SUSPENSION LIFTING: Automatic on expiry');
            console.log('• INVESTMENT COMPLETION: Automatic marking');
            console.log('• REAL-TIME NOTIFICATIONS: For all actions');
            console.log('============================================\n');
            
            console.log('✅ ALL ENDPOINTS PRESERVED AND ENHANCED');
            console.log('✅ IMMEDIATE INTEREST SYSTEM ACTIVE');
            console.log('✅ ENHANCED ADMIN CONTROLS ENABLED');
            console.log('✅ ENHANCED INTEREST RATES APPLIED');
            console.log('✅ PRODUCTION-READY WITH ALL FEATURES');
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
