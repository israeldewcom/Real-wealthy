// server.js - RAW WEALTHY BACKEND v52.0 - TWO-BALANCE SYSTEM ENHANCED EDITION
// ENHANCED WITH PRINCIPAL/EARNINGS SEPARATION, REINVESTMENT ONLY FROM PRINCIPAL
// ALL ORIGINAL ENDPOINTS PRESERVED AND UPGRADED

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
    
    // Business Logic
    minInvestment: parseInt(process.env.MIN_INVESTMENT) || 3500,
    minDeposit: parseInt(process.env.MIN_DEPOSIT) || 3500,
    minWithdrawal: parseInt(process.env.MIN_WITHDRAWAL) || 4000,
    maxWithdrawalPercent: parseFloat(process.env.MAX_WITHDRAWAL_PERCENT) || 100,
    
    platformFeePercent: parseFloat(process.env.PLATFORM_FEE_PERCENT) || 10,
    referralCommissionPercent: parseFloat(process.env.REFERRAL_COMMISSION_PERCENT) || 20,
    welcomeBonus: parseInt(process.env.WELCOME_BONUS) || 100,
    
    // Investment durations (days)
    planDurations: {
        firstThree: parseInt(process.env.PLAN_DURATION_FIRST_THREE) || 20,
        nextThree: parseInt(process.env.PLAN_DURATION_NEXT_THREE) || 15,
        remaining: parseInt(process.env.PLAN_DURATION_REMAINING) || 9
    },
    
    // Feature flags
    dailyInterestTime: process.env.DAILY_INTEREST_TIME || '00:00',
    withdrawalAutoApprove: process.env.WITHDRAWAL_AUTO_APPROVE === 'true' ? true : false,
    referralCommissionOnFirstInvestment: process.env.REFERRAL_COMMISSION_ON_FIRST_INVESTMENT !== 'false',
    allInvestmentsRequireAdminApproval: process.env.ALL_INVESTMENTS_REQUIRE_ADMIN_APPROVAL === 'true' ? true : false,
    deductBalanceOnlyOnApproval: process.env.DEDUCT_BALANCE_ONLY_ON_APPROVAL === 'true' ? true : false,
    
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
    },
    
    // System locks for cron jobs
    cronLocks: {
        dailyInterest: false,
        investmentCompletion: false
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

console.log('⚙️ Advanced Configuration Loaded:');
console.log(`- Port: ${config.port}`);
console.log(`- Environment: ${config.nodeEnv}`);
console.log(`- Client URL: ${config.clientURL}`);
console.log(`- Server URL: ${config.serverURL}`);
console.log(`- Email Enabled: ${config.emailEnabled}`);
console.log(`- Payment Enabled: ${config.paymentEnabled}`);
console.log(`- Withdrawal Auto-approve: ${config.withdrawalAutoApprove}`);
console.log(`- Daily Interest Time: ${config.dailyInterestTime}`);
console.log(`- Minimum Withdrawal: ₦${config.minWithdrawal.toLocaleString()}`);
console.log(`- Referral Commission: ${config.referralCommissionPercent}%`);
console.log(`- All Investments Require Admin Approval: ${config.allInvestmentsRequireAdminApproval}`);
console.log(`- Balance Deducted Only on Approval: ${config.deductBalanceOnlyOnApproval}`);
console.log(`- Investments Auto-Approved: ${!config.allInvestmentsRequireAdminApproval ? '✅ YES' : '❌ NO'}`);
console.log(`- Daily Interest Starts Immediately: ✅ YES`);
console.log(`- Interest Updates Every 24h: ✅ YES`);
console.log(`- Allowed Origins: ${config.allowedOrigins.length}`);

// ==================== ENHANCED EXPRESS SETUP WITH SOCKET.IO ====================
const app = express();
const server = http.createServer(app);
const io = new Server(server, {
    cors: {
        origin: config.allowedOrigins,
        credentials: true
    }
});

// Socket authentication middleware
io.use((socket, next) => {
    const token = socket.handshake.auth.token;
    if (!token) {
        return next(new Error('Authentication required'));
    }
    try {
        const decoded = jwt.verify(token, config.jwtSecret);
        socket.userId = decoded.id;
        socket.userRole = decoded.role;
        next();
    } catch (err) {
        next(new Error('Invalid token'));
    }
});

// Real-time connection handling with authentication
io.on('connection', (socket) => {
    console.log(`🔌 New authenticated socket connection: ${socket.id} (user: ${socket.userId})`);
    
    socket.on('join-user', (userId) => {
        if (userId === socket.userId) {
            socket.join(`user-${userId}`);
            console.log(`👤 User ${userId} joined their room`);
        } else {
            socket.emit('error', 'Unauthorized to join this room');
        }
    });
    
    socket.on('admin-join', (adminId) => {
        if (socket.userRole === 'admin' || socket.userRole === 'super_admin') {
            if (adminId === socket.userId) {
                socket.join(`admin-${adminId}`);
                socket.join('admin-room');
                socket.join('withdrawal-approvals');
                socket.join('investment-monitor');
                socket.join('deposit-approvals');
                console.log(`👨‍💼 Admin ${adminId} joined admin room`);
            } else {
                socket.emit('error', 'Unauthorized to join as another admin');
            }
        } else {
            socket.emit('error', 'Admin privileges required');
        }
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

const emitToWithdrawalAdmins = (event, data) => {
    io.to('withdrawal-approvals').emit(event, data);
};

const emitToDepositAdmins = (event, data) => {
    io.to('deposit-approvals').emit(event, data);
};

const emitToInvestmentAdmins = (event, data) => {
    io.to('investment-monitor').emit(event, data);
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

// ==================== ENHANCED FILE UPLOAD CONFIGURATION (DISK STORAGE) ====================
if (!fs.existsSync(config.uploadDir)) {
    fs.mkdirSync(config.uploadDir, { recursive: true });
    console.log('📁 Created main uploads directory');
}

// Disk storage configuration
const diskStorage = multer.diskStorage({
    destination: (req, file, cb) => {
        const folder = req.body.folder || 'general';
        const dest = path.join(config.uploadDir, folder);
        if (!fs.existsSync(dest)) {
            fs.mkdirSync(dest, { recursive: true });
        }
        cb(null, dest);
    },
    filename: (req, file, cb) => {
        const timestamp = Date.now();
        const randomStr = crypto.randomBytes(8).toString('hex');
        const ext = path.extname(file.originalname) || '.' + (config.allowedMimeTypes[file.mimetype] || 'bin');
        const filename = `${timestamp}_${randomStr}${ext}`;
        cb(null, filename);
    }
});

const fileFilter = (req, file, cb) => {
    if (!config.allowedMimeTypes[file.mimetype]) {
        return cb(new Error(`Invalid file type: ${file.mimetype}`), false);
    }
    cb(null, true);
};

const upload = multer({
    storage: diskStorage,
    fileFilter,
    limits: {
        fileSize: config.maxFileSize,
        files: 10
    }
});

const handleFileUpload = (file, folder = 'general', userId = null) => {
    return {
        url: `${config.serverURL}/uploads/${folder}/${file.filename}`,
        filename: file.filename,
        originalName: file.originalname,
        size: file.size,
        mimeType: file.mimetype
    };
};

// Serve uploaded files
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

// ==================== DATABASE MODELS - ENHANCED WITH TWO-BALANCE SYSTEM ====================
const userSchema = new mongoose.Schema({
    full_name: { type: String, required: true, trim: true },
    email: { type: String, required: true, unique: true, lowercase: true },
    phone: { type: String, required: true },
    password: { type: String, required: true, select: false },
    role: { type: String, enum: ['user', 'admin', 'super_admin'], default: 'user' },
    
    // Financial fields - ENHANCED with principal and earnings separation
    balance: { type: Number, default: 0, min: 0 }, // total balance (principal + earnings) - kept for backward compatibility
    principal_balance: { type: Number, default: 0, min: 0 }, // money from deposits, can be reinvested
    earnings_balance: { type: Number, default: 0, min: 0 }, // money from interest/referrals, withdrawable only
    
    total_earnings: { type: Number, default: 0, min: 0 }, // cumulative earnings from investments (historical)
    referral_earnings: { type: Number, default: 0, min: 0 }, // cumulative referral bonuses (historical)
    total_withdrawn: { type: Number, default: 0, min: 0 }, // cumulative amount withdrawn
    withdrawable_earnings: { type: Number, default: 0, min: 0 }, // updated to equal earnings_balance
    
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
    
    total_deposits: { type: Number, default: 0 },
    total_withdrawals: { type: Number, default: 0 },
    total_investments: { type: Number, default: 0 },
    last_deposit_date: Date,
    last_withdrawal_date: Date,
    last_investment_date: Date,
    last_daily_interest_date: Date,
    
    first_investment_amount: { type: Number, default: 0 },
    first_investment_date: Date,
    referral_commission_paid: { type: Boolean, default: false },
    
    login_history: [{
        ip: String,
        location: String,
        device: String,
        timestamp: { type: Date, default: Date.now }
    }],
    
    account_status: { 
        type: String, 
        enum: ['active', 'suspended', 'rejected', 'pending_verification'], 
        default: 'active' 
    },
    suspension_reason: String,
    suspension_date: Date,
    suspension_end_date: Date,
    suspended_by: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    
    last_interest_calculation: Date,
    next_interest_calculation: Date,
    
    auto_reinvest_earnings: { type: Boolean, default: false },
    auto_reinvest_percentage: { type: Number, default: 50, min: 0, max: 100 }
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
            
            ret.available_for_withdrawal = doc.availableForWithdrawal;
            ret.portfolio_value = doc.portfolioValue;
            ret.principal_balance = doc.principal_balance;
            ret.earnings_balance = doc.earnings_balance;
            return ret;
        }
    },
    toObject: { virtuals: true }
});

// Virtual field for available withdrawal - now based on earnings_balance
userSchema.virtual('availableForWithdrawal').get(function() {
    return Math.max(0, this.earnings_balance || 0);
});

// Virtual field for portfolio value - sum of principal and earnings (balance already includes both)
userSchema.virtual('portfolioValue').get(function() {
    return this.balance || 0;
});

// Method to get total active investments
userSchema.methods.getTotalActiveInvestments = async function() {
    const count = await mongoose.model('Investment').countDocuments({
        user: this._id,
        status: 'active'
    });
    return count || 0;
};

// Indexes
userSchema.index({ email: 1 }, { unique: true });
userSchema.index({ referral_code: 1 }, { unique: true, sparse: true });
userSchema.index({ is_active: 1, role: 1, kyc_status: 1 });
userSchema.index({ withdrawable_earnings: 1 });
userSchema.index({ account_status: 1 });
userSchema.index({ last_interest_calculation: 1 });
userSchema.index({ principal_balance: 1, earnings_balance: 1 });

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
    
    // Keep total balance in sync with principal + earnings
    this.balance = (this.principal_balance || 0) + (this.earnings_balance || 0);
    
    // Withdrawable earnings now equals earnings_balance (only earnings can be withdrawn)
    if (this.isModified('earnings_balance') || this.isModified('total_withdrawn')) {
        this.withdrawable_earnings = Math.max(0, this.earnings_balance || 0);
    }
    
    // Auto-activate user if admin and account_status is pending
    if (this.isModified('role') && this.role === 'admin' && this.account_status === 'pending_verification') {
        this.account_status = 'active';
        this.is_active = true;
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
            principal_balance: this.principal_balance,
            earnings_balance: this.earnings_balance,
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
    return Math.max(0, this.earnings_balance || 0);
};

userSchema.methods.suspendAccount = function(reason, adminId, durationDays = null) {
    this.account_status = 'suspended';
    this.is_active = false;
    this.suspension_reason = reason;
    this.suspension_date = new Date();
    this.suspended_by = adminId;
    
    if (durationDays) {
        this.suspension_end_date = new Date(Date.now() + durationDays * 24 * 60 * 60 * 1000);
    }
    
    return this;
};

userSchema.methods.activateAccount = function() {
    this.account_status = 'active';
    this.is_active = true;
    this.suspension_reason = null;
    this.suspension_date = null;
    this.suspension_end_date = null;
    this.suspended_by = null;
    
    return this;
};

userSchema.methods.rejectAccount = function(reason, adminId) {
    this.account_status = 'rejected';
    this.is_active = false;
    this.suspension_reason = reason;
    this.suspension_date = new Date();
    this.suspended_by = adminId;
    
    return this;
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

// Investment Model
const investmentSchema = new mongoose.Schema({
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    plan: { type: mongoose.Schema.Types.ObjectId, ref: 'InvestmentPlan', required: true },
    amount: { type: Number, required: true, min: config.minInvestment },
    status: { type: String, enum: ['pending', 'active', 'completed', 'cancelled', 'failed', 'rejected'], default: 'active' },
    start_date: { type: Date, default: Date.now },
    end_date: { type: Date, required: true },
    approved_at: { type: Date, default: Date.now },
    rejected_at: Date,
    rejected_by: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    rejection_reason: String,
    
    expected_earnings: { type: Number, required: true },
    earned_so_far: { type: Number, default: 0 },
    daily_earnings: { type: Number, default: 0 },
    last_earning_date: { type: Date, default: Date.now },
    next_interest_date: { type: Date, default: () => new Date(Date.now() + 24 * 60 * 60 * 1000) },
    interest_added_count: { type: Number, default: 1 },
    total_interest_days: { type: Number, default: 0 },
    
    payment_proof_url: String,
    payment_verified: { type: Boolean, default: true },
    auto_renew: { type: Boolean, default: false },
    auto_renewed: { type: Boolean, default: false },
    approved_by: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    transaction_id: String,
    remarks: String,
    
    balance_deducted: { type: Boolean, default: true },
    is_auto_approved: { type: Boolean, default: true },
    
    reversal_transaction_id: String,
    reversed_at: Date,
    
    metadata: { type: mongoose.Schema.Types.Mixed, default: {} }
}, {
    timestamps: true
});

investmentSchema.index({ user: 1, status: 1 });
investmentSchema.index({ end_date: 1 });
investmentSchema.index({ next_interest_date: 1 });
investmentSchema.index({ balance_deducted: 1 });
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
    rejected_by: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    rejected_at: Date,
    rejection_reason: String,
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
    
    from_earnings: { type: Number, default: 0 },
    from_principal: { type: Number, default: 0 },
    
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
    rejected_by: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    rejected_at: Date,
    rejection_reason: String,
    
    auto_approved: { type: Boolean, default: false },
    requires_admin_approval: { type: Boolean, default: true },
    
    admin_review_status: { 
        type: String, 
        enum: ['pending_review', 'under_review', 'approved', 'rejected'], 
        default: 'pending_review' 
    },
    reviewed_by: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    review_notes: String,
    review_date: Date,
    
    transaction_id_ref: { type: mongoose.Schema.Types.ObjectId, ref: 'Transaction' },
    
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
    principal_before: Number,
    principal_after: Number,
    earnings_before: Number,
    earnings_after: Number,
    
    earnings_before_cumulative: Number,
    earnings_after_cumulative: Number,
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
    
    commission_transaction_id: { type: mongoose.Schema.Types.ObjectId, ref: 'Transaction' },
    
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
        
        emitToUser(userId, 'new-notification', {
            title,
            message,
            type,
            action_url: actionUrl
        });
        
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

// ==================== ENHANCED createTransaction FUNCTION - TWO-BALANCE SUPPORT ====================
const createTransaction = async (userId, type, amount, description, status = 'completed', metadata = {}) => {
    console.log(`🔄 [TRANSACTION] Creating: ${type} for user ${userId}, amount: ${amount}, status: ${status}`);
    
    try {
        const user = await User.findById(userId);
        if (!user) {
            throw new Error(`User ${userId} not found`);
        }
        
        // Store before values
        const beforeState = {
            balance: user.balance || 0,
            principal_balance: user.principal_balance || 0,
            earnings_balance: user.earnings_balance || 0,
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
                        user.earnings_balance += amount;
                        user.total_earnings += amount;
                        // Balance auto-updates via pre-save
                        console.log(`💰 Added ${amount} to earnings_balance and total_earnings`);
                    }
                    break;
                    
                case 'referral_bonus':
                    if (amount > 0) {
                        user.earnings_balance += amount;
                        user.referral_earnings += amount;
                        console.log(`🎁 Added ${amount} to earnings_balance and referral_earnings`);
                    }
                    break;
                    
                case 'investment':
                    // Amount is negative for investment
                    const investmentAmount = Math.abs(amount);
                    // Deduct from principal_balance only
                    if (investmentAmount > user.principal_balance) {
                        throw new Error(`Insufficient principal balance for investment. Required: ${investmentAmount}, Available principal: ${user.principal_balance}`);
                    }
                    user.principal_balance -= investmentAmount;
                    user.total_investments = (user.total_investments || 0) + investmentAmount;
                    user.last_investment_date = new Date();
                    
                    // Track first investment
                    if (!user.first_investment_amount || user.first_investment_amount === 0) {
                        user.first_investment_amount = investmentAmount;
                        user.first_investment_date = new Date();
                    }
                    
                    console.log(`📈 Deducted ${investmentAmount} from principal_balance for investment`);
                    break;
                    
                case 'deposit':
                    if (amount > 0) {
                        user.principal_balance += amount;
                        user.total_deposits = (user.total_deposits || 0) + amount;
                        user.last_deposit_date = new Date();
                        console.log(`💵 Added ${amount} to principal_balance from deposit`);
                    }
                    break;
                    
                case 'withdrawal':
                    // Amount is negative for withdrawal
                    const withdrawalAmount = Math.abs(amount);
                    // Deduct from earnings_balance first, then from principal_balance if needed
                    let remaining = withdrawalAmount;
                    let fromEarnings = 0;
                    let fromPrincipal = 0;
                    
                    if (remaining > 0 && user.earnings_balance > 0) {
                        fromEarnings = Math.min(remaining, user.earnings_balance);
                        user.earnings_balance -= fromEarnings;
                        remaining -= fromEarnings;
                    }
                    if (remaining > 0) {
                        fromPrincipal = Math.min(remaining, user.principal_balance);
                        user.principal_balance -= fromPrincipal;
                        remaining -= fromPrincipal;
                    }
                    if (remaining > 0) {
                        // This shouldn't happen if we've checked availability earlier
                        throw new Error('Insufficient funds for withdrawal');
                    }
                    
                    user.total_withdrawn += withdrawalAmount;
                    user.total_withdrawals = (user.total_withdrawals || 0) + withdrawalAmount;
                    user.last_withdrawal_date = new Date();
                    
                    console.log(`💸 Withdrew ${withdrawalAmount} (from_earnings: ${fromEarnings}, from_principal: ${fromPrincipal})`);
                    
                    // Store in metadata for record
                    metadata.from_earnings = fromEarnings;
                    metadata.from_principal = fromPrincipal;
                    break;
                    
                case 'bonus':
                    if (amount > 0) {
                        user.earnings_balance += amount;
                        console.log(`🎉 Added ${amount} bonus to earnings_balance`);
                    }
                    break;
                    
                case 'refund':
                    if (amount > 0) {
                        user.principal_balance += amount;
                        console.log(`↩️ Refunded ${amount} to principal_balance`);
                    }
                    break;
            }
        }
        
        // Save user changes (pre-save hook will update balance)
        await user.save();
        console.log(`✅ [TRANSACTION] User updated successfully`);
        
        // After save, get final values
        const afterState = {
            balance: user.balance,
            principal_balance: user.principal_balance,
            earnings_balance: user.earnings_balance,
            total_earnings: user.total_earnings,
            referral_earnings: user.referral_earnings,
            withdrawable_earnings: user.withdrawable_earnings,
            total_withdrawn: user.total_withdrawn
        };
        
        // Create transaction record
        const transaction = new Transaction({
            user: userId,
            type,
            amount,
            description,
            status,
            reference: generateReference('TXN'),
            balance_before: beforeState.balance,
            balance_after: afterState.balance,
            principal_before: beforeState.principal_balance,
            principal_after: afterState.principal_balance,
            earnings_before: beforeState.earnings_balance,
            earnings_after: afterState.earnings_balance,
            earnings_before_cumulative: beforeState.total_earnings,
            earnings_after_cumulative: afterState.total_earnings,
            referral_earnings_before: beforeState.referral_earnings,
            referral_earnings_after: afterState.referral_earnings,
            withdrawable_before: beforeState.withdrawable_earnings,
            withdrawable_after: afterState.withdrawable_earnings,
            metadata: {
                ...metadata,
                processedAt: new Date(),
                user_id: userId,
                transaction_type: type
            }
        });
        
        await transaction.save();
        console.log(`✅ [TRANSACTION] Transaction record created: ${transaction._id}`);
        
        emitToUser(userId, 'balance-updated', {
            balance: afterState.balance,
            principal_balance: afterState.principal_balance,
            earnings_balance: afterState.earnings_balance,
            total_earnings: afterState.total_earnings,
            referral_earnings: afterState.referral_earnings,
            withdrawable_earnings: afterState.withdrawable_earnings,
            total_withdrawn: afterState.total_withdrawn,
            timestamp: new Date().toISOString()
        });
        
        console.log(`📊 [TRANSACTION] Final state:`, afterState);
        console.log(`🎯 [TRANSACTION] Completed successfully for user ${userId}`);
        return { success: true, transaction };
        
    } catch (error) {
        console.error(`❌ [TRANSACTION] Failed:`, error);
        return { success: false, error: error.message };
    }
};

// ==================== ADVANCED DAILY INTEREST HELPER FUNCTIONS ====================
const addDailyInterestForInvestment = async (investment) => {
    console.log(`💰 [INTEREST] Adding daily interest for investment: ${investment._id}`);
    
    try {
        if (investment.status !== 'active') {
            console.log(`❌ [INTEREST] Investment ${investment._id} is not active`);
            return { success: false, error: 'Investment not active' };
        }
        
        if (investment.end_date <= new Date()) {
            console.log(`❌ [INTEREST] Investment ${investment._id} has expired`);
            investment.status = 'completed';
            await investment.save();
            return { success: false, error: 'Investment expired' };
        }
        
        const plan = await InvestmentPlan.findById(investment.plan);
        if (!plan) {
            console.log(`❌ [INTEREST] Plan not found for investment: ${investment._id}`);
            return { success: false, error: 'Plan not found' };
        }
        
        const dailyEarning = (investment.amount * plan.daily_interest) / 100;
        
        investment.earned_so_far += dailyEarning;
        investment.interest_added_count += 1;
        investment.last_earning_date = new Date();
        investment.next_interest_date = new Date(Date.now() + 24 * 60 * 60 * 1000);
        
        await investment.save();
        
        await createTransaction(
            investment.user,
            'daily_interest',
            dailyEarning,
            `Daily interest from ${plan.name} investment (Day ${investment.interest_added_count})`,
            'completed',
            {
                investment_id: investment._id,
                plan_name: plan.name,
                daily_interest_rate: plan.daily_interest,
                investment_amount: investment.amount,
                interest_day: investment.interest_added_count,
                total_days: plan.duration,
                next_interest_date: investment.next_interest_date
            }
        );
        
        console.log(`✅ [INTEREST] Added daily interest: ₦${dailyEarning.toLocaleString()} for investment ${investment._id}`);
        
        if (investment.interest_added_count >= plan.duration) {
            investment.status = 'completed';
            await investment.save();
            
            await createNotification(
                investment.user,
                'Investment Completed',
                `Your investment in ${plan.name} has completed. Total earnings: ₦${investment.earned_so_far.toLocaleString()}`,
                'investment',
                '/investments'
            );
            
            console.log(`🎉 [INTEREST] Investment ${investment._id} completed successfully`);
        }
        
        return {
            success: true,
            dailyEarning,
            interestAddedCount: investment.interest_added_count,
            totalEarned: investment.earned_so_far,
            nextInterestDate: investment.next_interest_date
        };
        
    } catch (error) {
        console.error(`❌ [INTEREST] Error adding daily interest:`, error);
        return { success: false, error: error.message };
    }
};

// ==================== ENHANCED DAILY INTEREST SYSTEM ====================
const calculateDailyInterest = async () => {
    if (config.cronLocks.dailyInterest) {
        console.log('⏳ Daily interest cron already running, skipping...');
        return { success: false, message: 'Already running' };
    }
    
    config.cronLocks.dailyInterest = true;
    console.log('🔄 Running advanced daily interest calculation...');
    
    try {
        const now = new Date();
        const activeInvestments = await Investment.find({
            status: 'active',
            end_date: { $gt: now },
            $or: [
                { next_interest_date: { $lte: now } },
                { next_interest_date: { $exists: false } }
            ]
        }).populate('plan').populate('user');
        
        let totalInterestPaid = 0;
        let investmentsUpdated = 0;
        
        for (const investment of activeInvestments) {
            const result = await addDailyInterestForInvestment(investment);
            if (result.success) {
                totalInterestPaid += result.dailyEarning;
                investmentsUpdated++;
            }
        }
        
        console.log(`✅ Advanced daily interest calculation completed: ${investmentsUpdated} investments updated, ₦${totalInterestPaid.toLocaleString()} paid`);
        
        return {
            success: true,
            investmentsUpdated,
            totalInterestPaid
        };
    } catch (error) {
        console.error('❌ Error in advanced daily interest calculation:', error);
        return {
            success: false,
            error: error.message
        };
    } finally {
        config.cronLocks.dailyInterest = false;
    }
};

// ==================== AUTOMATIC FIRST DAY INTEREST FUNCTION ====================
const addFirstDayInterest = async (investment) => {
    try {
        console.log(`💰 [FIRST INTEREST] Adding first day interest for investment: ${investment._id}`);
        
        const plan = await InvestmentPlan.findById(investment.plan);
        if (!plan) {
            console.log(`❌ [FIRST INTEREST] Plan not found for investment: ${investment._id}`);
            return { success: false, error: 'Plan not found' };
        }
        
        const dailyEarning = (investment.amount * plan.daily_interest) / 100;
        
        investment.earned_so_far = dailyEarning;
        investment.interest_added_count = 1;
        investment.last_earning_date = new Date();
        investment.next_interest_date = new Date(Date.now() + 24 * 60 * 60 * 1000);
        investment.total_interest_days = plan.duration;
        
        await investment.save();
        
        await createTransaction(
            investment.user,
            'daily_interest',
            dailyEarning,
            `First day interest from ${plan.name} investment`,
            'completed',
            {
                investment_id: investment._id,
                plan_name: plan.name,
                daily_interest_rate: plan.daily_interest,
                investment_amount: investment.amount,
                interest_day: 1,
                total_days: plan.duration,
                next_interest_date: investment.next_interest_date,
                is_first_day: true
            }
        );
        
        console.log(`✅ [FIRST INTEREST] Added first day interest: ₦${dailyEarning.toLocaleString()} for investment ${investment._id}`);
        
        return {
            success: true,
            dailyEarning,
            nextInterestDate: investment.next_interest_date
        };
        
    } catch (error) {
        console.error(`❌ [FIRST INTEREST] Error:`, error);
        return { success: false, error: error.message };
    }
};

// ==================== ADVANCED REFERRAL COMMISSION FUNCTION ====================
const awardReferralCommission = async (referredUserId, investmentAmount, investmentId) => {
    try {
        console.log(`🎯 Checking referral commission for user ${referredUserId}, investment: ₦${investmentAmount}`);
        
        const referredUser = await User.findById(referredUserId);
        if (!referredUser || !referredUser.referred_by) {
            console.log('❌ No referrer found for this user');
            return { success: false, message: 'No referrer found' };
        }
        
        const userInvestments = await Investment.countDocuments({
            user: referredUserId,
            status: { $in: ['active', 'completed'] }
        });
        
        if (userInvestments > 1) {
            console.log('⚠️ Not first investment, skipping referral commission');
            return { success: false, message: 'Not first investment' };
        }
        
        const referral = await Referral.findOne({
            referred_user: referredUserId,
            referrer: referredUser.referred_by,
            first_investment_commission_paid: false
        });
        
        if (!referral) {
            console.log('⚠️ Referral commission already paid or referral not found');
            return { success: false, message: 'Commission already paid or referral not found' };
        }
        
        const commission = investmentAmount * (config.referralCommissionPercent / 100);
        
        const txResult = await createTransaction(
            referredUser.referred_by,
            'referral_bonus',
            commission,
            `Referral commission from ${referredUser.full_name}'s first investment (${config.referralCommissionPercent}%)`,
            'completed',
            {
                referred_user_id: referredUserId,
                investment_id: investmentId,
                commission_percentage: config.referralCommissionPercent,
                first_investment_amount: investmentAmount
            }
        );
        
        if (!txResult.success) {
            throw new Error('Failed to create transaction for referral commission');
        }
        
        referral.total_commission = commission;
        referral.first_investment_commission_paid = true;
        referral.first_investment_amount = investmentAmount;
        referral.first_investment_date = new Date();
        referral.earnings_paid = true;
        referral.paid_at = new Date();
        referral.status = 'completed';
        referral.commission_transaction_id = txResult.transaction._id;
        await referral.save();
        
        await createNotification(
            referredUser.referred_by,
            'Referral Commission Earned!',
            `You earned ₦${commission.toLocaleString()} commission (${config.referralCommissionPercent}%) from ${referredUser.full_name}'s first investment.`,
            'referral',
            '/referrals'
        );
        
        console.log(`✅ Referral commission awarded: ₦${commission.toLocaleString()} (${config.referralCommissionPercent}%) to user ${referredUser.referred_by}`);
        
        return {
            success: true,
            commission,
            referrerId: referredUser.referred_by,
            referredUserId: referredUserId,
            commission_percentage: config.referralCommissionPercent,
            transaction: txResult.transaction
        };
    } catch (error) {
        console.error('❌ Error awarding referral commission:', error);
        return {
            success: false,
            error: error.message
        };
    }
};

// AML Monitoring function
const checkAmlCompliance = async (userId, transactionType, amount, metadata = {}) => {
    try {
        if (amount <= 0) return { riskScore: 0, flagged: false };
        
        let riskScore = 0;
        let flaggedReasons = [];
        
        if (amount > 1000000) {
            riskScore += 40;
            flaggedReasons.push('Large transaction amount');
        }
        
        if (amount > 500000 && transactionType === 'withdrawal') {
            riskScore += 30;
            flaggedReasons.push('Large withdrawal request');
        }
        
        const recentTransactions = await Transaction.countDocuments({
            user: userId,
            createdAt: { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) }
        });
        
        if (recentTransactions > 10) {
            riskScore += 20;
            flaggedReasons.push('High transaction frequency');
        }
        
        const user = await User.findById(userId);
        if (user) {
            const accountAgeDays = (new Date() - user.createdAt) / (1000 * 60 * 60 * 24);
            if (accountAgeDays < 7 && amount > 100000) {
                riskScore += 30;
                flaggedReasons.push('New account with large transaction');
            }
        }
        
        if (riskScore > 50) {
            const amlRecord = new AmlMonitoring({
                user: userId,
                transaction_type: transactionType,
                amount,
                flagged_reason: flaggedReasons.join(', '),
                risk_score: riskScore,
                status: 'pending_review',
                metadata
            });
            
            await amlRecord.save();
            
            emitToAdmins('aml-flagged', {
                userId,
                transactionType,
                amount,
                riskScore,
                reasons: flaggedReasons
            });
            
            console.log(`🚨 AML Flagged: User ${userId}, Risk Score: ${riskScore}, Reasons: ${flaggedReasons.join(', ')}`);
        }
        
        return {
            riskScore,
            flagged: riskScore > 50,
            reasons: flaggedReasons
        };
    } catch (error) {
        console.error('AML check error:', error);
        return { riskScore: 0, flagged: false, reasons: [] };
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
        
        if (user.account_status === 'suspended') {
            return res.status(403).json(formatResponse(false, 'Account is suspended. Please contact support.'));
        }
        
        if (user.account_status === 'rejected') {
            return res.status(403).json(formatResponse(false, 'Account has been rejected. Please contact support.'));
        }
        
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
            serverSelectionTimeoutMS: 5000,
            socketTimeoutMS: 45000,
            maxPoolSize: 10,
            retryWrites: true
        });
        
        console.log('✅ MongoDB connected successfully');
        await createAdminUser();
        await createDefaultInvestmentPlans();
        
        // Migrate existing users to initialize principal_balance and earnings_balance
        await migrateUserBalances();
        
        console.log('✅ Database initialization completed');
    } catch (error) {
        console.error('❌ Database initialization error:', error.message);
        throw error;
    }
};

const migrateUserBalances = async () => {
    console.log('🔄 Migrating user balances to two-balance system...');
    try {
        // For existing users, we set principal_balance = balance (assuming all funds are principal)
        // and earnings_balance = 0. This ensures they can still reinvest all their funds.
        // As they earn interest, earnings_balance will increase separately.
        const result = await User.updateMany(
            { principal_balance: 0, earnings_balance: 0 },
            [
                { $set: { principal_balance: "$balance", earnings_balance: 0 } }
            ]
        );
        console.log(`✅ Migrated ${result.modifiedCount} users`);
    } catch (error) {
        console.error('❌ Balance migration error:', error);
    }
};

const createDefaultInvestmentPlans = async () => {
    const firstThreeDuration = config.planDurations.firstThree;
    const nextThreeDuration = config.planDurations.nextThree;
    const remainingDuration = config.planDurations.remaining;
    
    const defaultPlans = [
        {
            name: 'Cocoa Beans',
            description: 'Invest in premium cocoa beans with stable returns.',
            min_amount: 3500,
            max_amount: 50000,
            daily_interest: 15,
            total_interest: 15 * firstThreeDuration,
            duration: firstThreeDuration,
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
            description: 'Precious metal investment with high liquidity.',
            min_amount: 50000,
            max_amount: 500000,
            daily_interest: 20,
            total_interest: 20 * firstThreeDuration,
            duration: firstThreeDuration,
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
            description: 'Energy sector investment with premium returns.',
            min_amount: 100000,
            max_amount: 1000000,
            daily_interest: 25,
            total_interest: 25 * firstThreeDuration,
            duration: firstThreeDuration,
            risk_level: 'high',
            raw_material: 'Crude Oil',
            category: 'energy',
            is_popular: true,
            features: ['High Risk', 'Maximum Returns', 'Premium Investment', 'Energy Sector'],
            color: '#dc2626',
            icon: '🛢️',
            display_order: 3
        },
        {
            name: 'Coffee Beans',
            description: 'Premium Arabica coffee beans from Ethiopian highlands.',
            min_amount: 5500,
            max_amount: 25000,
            daily_interest: 19,
            total_interest: 19 * nextThreeDuration,
            duration: nextThreeDuration,
            risk_level: 'low',
            raw_material: 'Coffee',
            category: 'agriculture',
            is_popular: false,
            features: ['Very Low Risk', 'Consistent Returns', 'Global Demand', 'Daily Payouts'],
            color: '#8B4513',
            icon: '☕',
            display_order: 4
        },
        {
            name: 'Silver Bullion',
            description: 'Industrial silver with growing demand in technology sector.',
            min_amount: 15000,
            max_amount: 150000,
            daily_interest: 17,
            total_interest: 17 * nextThreeDuration,
            duration: nextThreeDuration,
            risk_level: 'medium',
            raw_material: 'Silver',
            category: 'metals',
            is_popular: false,
            features: ['Medium Risk', 'Industrial Demand', 'Portfolio Diversification', 'Regular Returns'],
            color: '#C0C0C0',
            icon: '🥈',
            display_order: 5
        },
        {
            name: 'Timber (Teak)',
            description: 'Premium Teak wood with high value in construction and furniture.',
            min_amount: 20000,
            max_amount: 200000,
            daily_interest: 19,
            total_interest: 19 * nextThreeDuration,
            duration: nextThreeDuration,
            risk_level: 'medium',
            raw_material: 'Teak Wood',
            category: 'timber',
            is_popular: false,
            features: ['Sustainable', 'High Demand', 'Long-term Value', 'Environmental Impact'],
            color: '#8B4513',
            icon: '🌳',
            display_order: 6
        },
        {
            name: 'Natural Gas',
            description: 'Clean energy source with increasing global demand.',
            min_amount: 75000,
            max_amount: 750000,
            daily_interest: 23,
            total_interest: 23 * remainingDuration,
            duration: remainingDuration,
            risk_level: 'high',
            raw_material: 'Natural Gas',
            category: 'energy',
            is_popular: false,
            features: ['High Returns', 'Energy Transition', 'Global Market', 'Premium Investment'],
            color: '#4169E1',
            icon: '🔥',
            display_order: 7
        },
        {
            name: 'Aquaculture (Salmon)',
            description: 'Premium salmon farming with sustainable practices.',
            min_amount: 30000,
            max_amount: 300000,
            daily_interest: 21,
            total_interest: 21 * remainingDuration,
            duration: remainingDuration,
            risk_level: 'medium',
            raw_material: 'Salmon',
            category: 'aquaculture',
            is_popular: false,
            features: ['Sustainable Farming', 'High Nutritional Value', 'Growing Demand', 'Regular Returns'],
            color: '#FF6B6B',
            icon: '🐟',
            display_order: 8
        }
    ];
    
    try {
        for (const planData of defaultPlans) {
            const existingPlan = await InvestmentPlan.findOne({ name: planData.name });
            if (!existingPlan) {
                await InvestmentPlan.create(planData);
                console.log(`✅ Created investment plan: ${planData.name} (${planData.daily_interest}% daily, ${planData.duration} days)`);
            } else {
                await InvestmentPlan.findByIdAndUpdate(existingPlan._id, planData);
                console.log(`✅ Updated investment plan: ${planData.name} (${planData.daily_interest}% daily, ${planData.duration} days)`);
            }
        }
        console.log('✅ Default investment plans created/verified');
    } catch (error) {
        console.error('Error creating default investment plans:', error);
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
            principal_balance: 1000000,
            earnings_balance: 0,
            total_earnings: 500000,
            referral_earnings: 200000,
            withdrawable_earnings: 0,
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
            'Your admin account has been successfully created.',
            'success',
            '/admin/dashboard'
        );
        
        console.log('\n🎉 =========== ADMIN SETUP COMPLETED ===========');
        console.log(`📧 Login Email: ${adminEmail}`);
        console.log(`🔑 Login Password: ${adminPassword}`);
        console.log(`👉 Login at: ${config.clientURL}/admin/login`);
        console.log('============================================\n');
        
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
        version: '52.0.0',
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
        message: '🚀 Raw Wealthy Backend v52.0 - Two-Balance System Enhanced Edition',
        version: '52.0.0',
        timestamp: new Date().toISOString(),
        status: 'Operational',
        environment: config.nodeEnv,
        features: {
            investment_auto_approval: '✅ ENABLED',
            daily_interest_auto: '✅ ENABLED',
            referral_commission: `${config.referralCommissionPercent}%`,
            admin_controls: '✅ ENABLED',
            real_time_updates: '✅ ENABLED',
            atomic_transactions: '✅ ENABLED',
            secure_sockets: '✅ ENABLED',
            two_balance_system: '✅ ENABLED (principal/earnings separation)'
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

// ==================== ENHANCED DEBUGGING ENDPOINTS - PROTECTED ====================
app.get('/api/debug/earnings-status/:userId', auth, async (req, res) => {
    try {
        const userId = req.params.userId;
        
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
        
        res.json({
            success: true,
            user: {
                email: user.email,
                stored: {
                    balance: user.balance,
                    principal_balance: user.principal_balance,
                    earnings_balance: user.earnings_balance,
                    total_earnings: user.total_earnings,
                    referral_earnings: user.referral_earnings,
                    withdrawable_earnings: user.withdrawable_earnings,
                    total_withdrawn: user.total_withdrawn
                }
            },
            transactions: {
                count: transactions.length,
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
                list: investments.map(i => ({
                    plan: i.plan?.name,
                    amount: i.amount,
                    earned_so_far: i.earned_so_far,
                    status: i.status
                }))
            }
        });
    } catch (error) {
        console.error('Earnings status error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

app.get('/api/debug/system-status', adminAuth, async (req, res) => {
    try {
        const systemStatus = {
            success: true,
            timestamp: new Date().toISOString(),
            system: {
                nodeVersion: process.version,
                platform: process.platform,
                uptime: process.uptime(),
                memoryUsage: process.memoryUsage(),
                cpuUsage: process.cpuUsage()
            },
            database: {
                connected: mongoose.connection.readyState === 1,
                host: mongoose.connection.host,
                name: mongoose.connection.name,
                models: Object.keys(mongoose.connection.models)
            },
            config: {
                environment: config.nodeEnv,
                serverURL: config.serverURL,
                clientURL: config.clientURL,
                emailEnabled: config.emailEnabled,
                paymentEnabled: config.paymentEnabled,
                withdrawalAutoApprove: config.withdrawalAutoApprove,
                referralCommissionOnFirstInvestment: config.referralCommissionOnFirstInvestment,
                referralCommissionPercent: config.referralCommissionPercent,
                allInvestmentsRequireAdminApproval: config.allInvestmentsRequireAdminApproval,
                deductBalanceOnlyOnApproval: config.deductBalanceOnlyOnApproval,
                minWithdrawal: config.minWithdrawal,
                planDurations: config.planDurations
            }
        };
        
        res.json(systemStatus);
    } catch (error) {
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
            principal_balance: config.welcomeBonus,
            earnings_balance: 0,
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
                status: 'pending',
                commission_percentage: config.referralCommissionPercent
            });
            
            await referral.save();
            
            await createNotification(
                referredBy._id,
                'New Referral!',
                `${user.full_name} has signed up using your referral code! You will earn ${config.referralCommissionPercent}% commission on their first investment.`,
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
        
        // Welcome bonus transaction
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
                    <li>Referral Commission: ${config.referralCommissionPercent}% on first investment</li>
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
        
        if (user.account_status === 'suspended') {
            const message = user.suspension_reason 
                ? `Account suspended. Reason: ${user.suspension_reason}. Contact support.`
                : 'Account suspended. Please contact support.';
            return res.status(403).json(formatResponse(false, message));
        }
        
        if (user.account_status === 'rejected') {
            return res.status(403).json(formatResponse(false, 'Account has been rejected. Please contact support.'));
        }
        
        const isMatch = await user.comparePassword(password);
        if (!isMatch) {
            return res.status(400).json(formatResponse(false, 'Invalid credentials'));
        }
        
        user.last_login = new Date();
        user.last_active = new Date();
        
        user.login_history.push({
            ip: req.ip,
            location: req.headers['x-forwarded-for'] || req.connection.remoteAddress,
            device: req.headers['user-agent'],
            timestamp: new Date()
        });
        
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
                principal_balance: userData.principal_balance || 0,
                earnings_balance: userData.earnings_balance || 0,
                total_earnings: userData.total_earnings || 0,
                referral_earnings: userData.referral_earnings || 0,
                withdrawable_earnings: userData.withdrawable_earnings || 0,
                available_for_withdrawal: userData.availableForWithdrawal || 0,
                daily_interest: dailyInterest,
                
                total_investments: investments,
                active_investments: activeInvestments.length,
                total_deposits: deposits,
                total_withdrawals: withdrawals,
                referral_count: referrals,
                active_investment_value: activeInvestmentValue,
                portfolio_value: userData.portfolioValue
            }
        };
        
        res.json(formatResponse(true, 'Profile retrieved successfully', profileData));
    } catch (error) {
        console.error('Error fetching profile:', error);
        handleError(res, error, 'Error fetching profile');
    }
});

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
        const allowedFields = ['full_name', 'phone', 'country', 'risk_tolerance', 
                               'investment_strategy', 'email_notifications', 'sms_notifications'];
        
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

// ==================== PASSWORD RESET ENDPOINTS ====================
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
        
        const resetToken = user.generatePasswordResetToken();
        await user.save();
        
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
        
        user.password = password;
        user.password_reset_token = undefined;
        user.password_reset_expires = undefined;
        await user.save();
        
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
app.get('/api/plans', async (req, res) => {
    try {
        const plans = await InvestmentPlan.find({ is_active: true })
            .sort({ display_order: 1, min_amount: 1 })
            .lean();
        
        const categorizedPlans = {
            beginner: plans.filter(p => p.min_amount <= 10000 && p.risk_level === 'low'),
            intermediate: plans.filter(p => p.min_amount > 10000 && p.min_amount <= 50000 && p.risk_level === 'medium'),
            advanced: plans.filter(p => p.min_amount > 50000 && p.risk_level === 'high'),
            popular: plans.filter(p => p.is_popular === true)
        };
        
        res.json(formatResponse(true, 'Plans retrieved successfully', { 
            plans,
            categorized: categorizedPlans,
            summary: {
                total_plans: plans.length,
                low_risk: plans.filter(p => p.risk_level === 'low').length,
                medium_risk: plans.filter(p => p.risk_level === 'medium').length,
                high_risk: plans.filter(p => p.risk_level === 'high').length,
                price_range: {
                    min: plans.reduce((min, plan) => Math.min(min, plan.min_amount), Infinity),
                    max: plans.reduce((max, plan) => Math.max(max, plan.max_amount || plan.min_amount), 0)
                }
            }
        }));
    } catch (error) {
        handleError(res, error, 'Error fetching investment plans');
    }
});

// ==================== INVESTMENT ENDPOINTS - AUTOMATIC APPROVAL ====================
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

// ==================== ENHANCED INVESTMENT CREATION - TWO-BALANCE CHECK ====================
app.post('/api/investments', auth, upload.single('payment_proof'), [
    body('plan_id').notEmpty(),
    body('amount').isFloat({ min: config.minInvestment }),
    body('auto_renew').optional().isBoolean()
], async (req, res) => {
    const session = await mongoose.startSession();
    session.startTransaction();
    
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            await session.abortTransaction();
            session.endSession();
            return res.status(400).json(formatResponse(false, 'Validation failed'));
        }
        
        const { plan_id, amount, auto_renew = false } = req.body;
        const userId = req.user._id;
        
        const freshUser = await User.findById(userId).session(session);
        if (!freshUser) {
            await session.abortTransaction();
            session.endSession();
            return res.status(404).json(formatResponse(false, 'User not found'));
        }
        
        const plan = await InvestmentPlan.findById(plan_id).session(session);
        if (!plan) {
            await session.abortTransaction();
            session.endSession();
            return res.status(404).json(formatResponse(false, 'Investment plan not found'));
        }
        
        const investmentAmount = parseFloat(amount);
        
        if (investmentAmount < plan.min_amount) {
            await session.abortTransaction();
            session.endSession();
            return res.status(400).json(formatResponse(false,
                `Minimum investment for ${plan.name} is ₦${plan.min_amount.toLocaleString()}`));
        }
        
        if (plan.max_amount && investmentAmount > plan.max_amount) {
            await session.abortTransaction();
            session.endSession();
            return res.status(400).json(formatResponse(false,
                `Maximum investment for ${plan.name} is ₦${plan.max_amount.toLocaleString()}`));
        }
        
        // Check if user has sufficient principal balance (not total balance)
        if (investmentAmount > freshUser.principal_balance) {
            await session.abortTransaction();
            session.endSession();
            return res.status(400).json(formatResponse(false, 
                `Insufficient principal balance for investment. Available principal: ₦${freshUser.principal_balance.toLocaleString()}, Required: ₦${investmentAmount.toLocaleString()}. Earnings (₦${freshUser.earnings_balance.toLocaleString()}) must be withdrawn first before reinvesting.`));
        }
        
        let proofUrl = null;
        if (req.file) {
            try {
                const uploadResult = handleFileUpload(req.file, 'investment-proofs', userId);
                proofUrl = uploadResult.url;
            } catch (uploadError) {
                await session.abortTransaction();
                session.endSession();
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
            status: 'active',
            start_date: new Date(),
            end_date: endDate,
            expected_earnings: expectedEarnings,
            daily_earnings: dailyEarnings,
            auto_renew,
            payment_proof_url: proofUrl,
            payment_verified: true,
            balance_deducted: true,
            is_auto_approved: true,
            next_interest_date: nextInterestDate,
            total_interest_days: plan.duration
        });
        
        await investment.save({ session });
        
        // Deduct from principal_balance using createTransaction (which handles balance update)
        const txResult = await createTransaction(
            userId,
            'investment',
            -investmentAmount,
            `Investment in ${plan.name} plan`,
            'completed',
            {
                plan_name: plan.name,
                plan_duration: plan.duration,
                daily_interest: plan.daily_interest,
                auto_approved: true,
                investment_id: investment._id
            }
        );
        
        if (!txResult.success) {
            throw new Error('Investment transaction failed');
        }
        
        // Add first day's interest immediately
        const dailyEarning = (investmentAmount * plan.daily_interest) / 100;
        investment.earned_so_far = dailyEarning;
        investment.interest_added_count = 1;
        investment.last_earning_date = new Date();
        await investment.save({ session });
        
        // Credit first day interest to earnings_balance
        const interestTx = await createTransaction(
            userId,
            'daily_interest',
            dailyEarning,
            `First day interest from ${plan.name} investment`,
            'completed',
            {
                plan_name: plan.name,
                daily_interest_rate: plan.daily_interest,
                investment_amount: investmentAmount,
                interest_day: 1,
                is_first_day: true,
                investment_id: investment._id
            }
        );
        
        if (!interestTx.success) {
            throw new Error('First day interest transaction failed');
        }
        
        // Update plan statistics
        await InvestmentPlan.findByIdAndUpdate(plan_id, {
            $inc: {
                investment_count: 1,
                total_invested: investmentAmount
            }
        }, { session });
        
        await session.commitTransaction();
        session.endSession();
        
        const userInvestmentsCount = await Investment.countDocuments({
            user: userId,
            status: { $in: ['active', 'completed'] }
        });
        
        if (userInvestmentsCount === 1 && config.referralCommissionOnFirstInvestment) {
            await awardReferralCommission(userId, investmentAmount, investment._id);
        }
        
        await createNotification(
            userId,
            'Investment Successfully Created!',
            `Your investment of ₦${investmentAmount.toLocaleString()} in ${plan.name} has been automatically approved and is now active. First day interest of ₦${dailyEarning.toLocaleString()} has been credited to your earnings balance.`,
            'investment',
            '/investments'
        );
        
        emitToAdmins('new-investment', {
            investment_id: investment._id,
            user_id: userId,
            user_name: freshUser.full_name,
            amount: investmentAmount,
            plan_name: plan.name,
            auto_approved: true,
            timestamp: new Date().toISOString()
        });
        
        // Fetch updated user to get latest balances
        const updatedUser = await User.findById(userId);
        
        res.status(201).json(formatResponse(true, 'Investment created and activated successfully!', {
            investment: {
                ...investment.toObject(),
                plan_name: plan.name,
                expected_daily_earnings: dailyEarnings,
                expected_total_earnings: expectedEarnings,
                end_date: endDate,
                auto_approved: true,
                first_day_interest: dailyEarning,
                next_interest_date: investment.next_interest_date
            },
            user_balance: {
                total_balance: updatedUser.balance,
                principal_balance: updatedUser.principal_balance,
                earnings_balance: updatedUser.earnings_balance
            }
        }));
    } catch (error) {
        await session.abortTransaction();
        session.endSession();
        handleError(res, error, 'Error creating investment');
    }
});

// ==================== DEPOSIT ENDPOINTS ====================
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
                approved_count: deposits.filter(d => d.status === 'approved').length,
                pending_count: deposits.filter(d => d.status === 'pending').length
            },
            pagination
        }));
    } catch (error) {
        handleError(res, error, 'Error fetching deposits');
    }
});

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
        
        const amlCheck = await checkAmlCompliance(userId, 'deposit', depositAmount);
        if (amlCheck.flagged) {
            return res.status(400).json(formatResponse(false, 
                'Deposit flagged for review due to compliance checks. Please contact support.'));
        }
        
        let proofUrl = null;
        if (req.file) {
            try {
                const uploadResult = handleFileUpload(req.file, 'deposit-proofs', userId);
                proofUrl = uploadResult.url;
            } catch (uploadError) {
                return res.status(400).json(formatResponse(false, `File upload failed: ${uploadError.message}`));
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
            `Your deposit request of ₦${depositAmount.toLocaleString()} has been submitted and is pending approval.`,
            'deposit',
            '/deposits'
        );
        
        emitToDepositAdmins('new-deposit', {
            deposit_id: deposit._id,
            user_id: userId,
            amount: depositAmount,
            payment_method,
            requires_approval: true
        });
        
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

// ==================== WITHDRAWAL ENDPOINTS - ADVANCED WITH ADMIN APPROVAL ====================
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
        
        const freshUser = await User.findById(userId);
        if (!freshUser) {
            return res.status(404).json(formatResponse(false, 'User not found'));
        }
        
        if (withdrawalAmount < config.minWithdrawal) {
            return res.status(400).json(formatResponse(false,
                `Minimum withdrawal is ₦${config.minWithdrawal.toLocaleString()}`));
        }
        
        // Check available earnings for withdrawal
        const availableForWithdrawal = freshUser.earnings_balance || 0;
        
        if (withdrawalAmount > availableForWithdrawal) {
            return res.status(400).json(formatResponse(false,
                `Insufficient earnings. Available for withdrawal: ₦${availableForWithdrawal.toLocaleString()}`));
        }
        
        const maxWithdrawal = availableForWithdrawal * (config.maxWithdrawalPercent / 100);
        if (withdrawalAmount > maxWithdrawal) {
            return res.status(400).json(formatResponse(false,
                `Maximum withdrawal is ${config.maxWithdrawalPercent}% of your available earnings (₦${maxWithdrawal.toLocaleString()})`));
        }
        
        if (payment_method === 'bank_transfer') {
            if (!freshUser.bank_details || !freshUser.bank_details.account_number) {
                return res.status(400).json(formatResponse(false, 'Please update your bank details in profile settings'));
            }
        } else if (payment_method === 'crypto') {
            if (!freshUser.wallet_address) {
                return res.status(400).json(formatResponse(false, 'Please set your wallet address in profile settings'));
            }
        } else if (payment_method === 'paypal') {
            if (!freshUser.paypal_email) {
                return res.status(400).json(formatResponse(false, 'Please set your PayPal email in profile settings'));
            }
        }
        
        const amlCheck = await checkAmlCompliance(userId, 'withdrawal', withdrawalAmount);
        if (amlCheck.flagged) {
            return res.status(400).json(formatResponse(false, 
                'Withdrawal flagged for review due to compliance checks. Please contact support.'));
        }
        
        const platformFee = withdrawalAmount * (config.platformFeePercent / 100);
        const netAmount = withdrawalAmount - platformFee;
        
        const requiresAdminApproval = true;
        
        // Create pending transaction
        const pendingTransaction = await createTransaction(
            userId,
            'withdrawal',
            -withdrawalAmount,
            `Withdrawal request via ${payment_method} - Pending Admin Approval`,
            'pending',
            {
                payment_method,
                platform_fee: platformFee,
                net_amount: netAmount,
                requires_admin_approval: true
            }
        );
        
        if (!pendingTransaction.success) {
            throw new Error('Failed to create pending transaction');
        }
        
        // Create withdrawal record (amount will be deducted from earnings_balance upon approval)
        const withdrawal = new Withdrawal({
            user: userId,
            amount: withdrawalAmount,
            payment_method,
            from_earnings: withdrawalAmount,
            from_principal: 0,
            platform_fee: platformFee,
            net_amount: netAmount,
            status: 'pending',
            reference: generateReference('WDL'),
            requires_admin_approval: requiresAdminApproval,
            auto_approved: false,
            admin_review_status: 'pending_review',
            
            ...(payment_method === 'bank_transfer' && freshUser.bank_details ? {
                bank_details: freshUser.bank_details
            } : {}),
            ...(payment_method === 'crypto' ? {
                wallet_address: freshUser.wallet_address
            } : {}),
            ...(payment_method === 'paypal' ? {
                paypal_email: freshUser.paypal_email
            } : {}),
            
            transaction_id_ref: pendingTransaction.transaction._id
        });
        
        await withdrawal.save();
        
        pendingTransaction.transaction.related_withdrawal = withdrawal._id;
        await pendingTransaction.transaction.save();
        
        await createNotification(
            userId,
            'Withdrawal Request Submitted',
            `Your withdrawal request of ₦${withdrawalAmount.toLocaleString()} has been submitted and is pending admin approval.`,
            'withdrawal',
            '/withdrawals'
        );
        
        emitToWithdrawalAdmins('new-withdrawal-request', {
            withdrawal_id: withdrawal._id,
            user_id: userId,
            user_name: freshUser.full_name,
            amount: withdrawalAmount,
            payment_method,
            net_amount: netAmount,
            platform_fee: platformFee,
            timestamp: new Date().toISOString(),
            requires_immediate_attention: withdrawalAmount > 50000
        });
        
        emitToAdmins('new-withdrawal', {
            withdrawal_id: withdrawal._id,
            user_id: userId,
            amount: withdrawalAmount,
            payment_method,
            auto_approved: false
        });
        
        res.status(201).json(formatResponse(true, 
            'Withdrawal request submitted successfully! It is now pending admin approval.', {
            withdrawal: {
                ...withdrawal.toObject(),
                formatted_amount: `₦${withdrawalAmount.toLocaleString()}`,
                formatted_net_amount: `₦${netAmount.toLocaleString()}`,
                formatted_fee: `₦${platformFee.toLocaleString()}`,
                requires_admin_approval: true,
                auto_approved: false,
                admin_review_status: 'pending_review'
            }
        }));
    } catch (error) {
        handleError(res, error, 'Error creating withdrawal');
    }
});

// ==================== TRANSACTION ENDPOINTS ====================
app.get('/api/transactions', auth, async (req, res) => {
    try {
        const userId = req.user._id;
        const { type, status, start_date, end_date, page = 1, limit = 20 } = req.query;
        
        const query = { user: userId };
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
            idFrontUrl = handleFileUpload(files.id_front[0], 'kyc-documents', userId).url;
            selfieWithIdUrl = handleFileUpload(files.selfie_with_id[0], 'kyc-documents', userId).url;
            
            if (files.id_back && files.id_back[0]) {
                idBackUrl = handleFileUpload(files.id_back[0], 'kyc-documents', userId).url;
            }
            
            if (files.address_proof && files.address_proof[0]) {
                addressProofUrl = handleFileUpload(files.address_proof[0], 'kyc-documents', userId).url;
            }
        } catch (uploadError) {
            return res.status(400).json(formatResponse(false, `File upload failed: ${uploadError.message}`));
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
            'Your KYC documents have been submitted successfully. Verification typically takes 24-48 hours.',
            'kyc',
            '/kyc'
        );
        
        emitToAdmins('new-kyc', {
            kyc_id: kycSubmission._id,
            user_id: userId,
            id_type
        });
        
        res.status(201).json(formatResponse(true, 'KYC submitted successfully!', {
            kyc: kycSubmission
        }));
    } catch (error) {
        handleError(res, error, 'Error submitting KYC');
    }
});

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
                const uploadResult = handleFileUpload(file, 'support-attachments', userId);
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
            `Your support ticket #${ticketId} has been created successfully. We will respond within 24 hours.`,
            'info',
            `/support/ticket/${ticketId}`
        );
        
        emitToAdmins('new-support-ticket', {
            ticket_id: ticketId,
            user_id: userId,
            subject,
            priority
        });
        
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

// ==================== REFERRAL ENDPOINTS ====================
app.get('/api/referrals/stats', auth, async (req, res) => {
    try {
        const userId = req.user._id;
        
        const referrals = await Referral.find({ referrer: userId })
            .populate('referred_user', 'full_name email createdAt balance first_investment_amount')
            .sort({ createdAt: -1 })
            .lean();
        
        const user = await User.findById(userId);
        
        let totalFirstInvestmentCommission = 0;
        referrals.forEach(ref => {
            if (ref.first_investment_commission_paid && ref.first_investment_amount) {
                totalFirstInvestmentCommission += ref.first_investment_amount * (config.referralCommissionPercent / 100);
            }
        });
        
        res.json(formatResponse(true, 'Referral stats retrieved successfully', {
            stats: {
                total_referrals: referrals.length,
                active_referrals: referrals.filter(r => r.status === 'active').length,
                referral_earnings: user.referral_earnings || 0,
                first_investment_commission: totalFirstInvestmentCommission,
                referral_code: user.referral_code,
                referral_link: `${config.clientURL}/register?ref=${user.referral_code}`,
                commission_rate: `${config.referralCommissionPercent}% (First investment only)`
            },
            referrals: referrals.slice(0, 10).map(ref => ({
                ...ref,
                first_investment_commission: ref.first_investment_amount ? 
                    ref.first_investment_amount * (config.referralCommissionPercent / 100) : 0
            }))
        }));
    } catch (error) {
        handleError(res, error, 'Error fetching referral stats');
    }
});

// ==================== NOTIFICATION ENDPOINTS ====================
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
app.post('/api/upload', auth, upload.single('file'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json(formatResponse(false, 'No file uploaded'));
        }
        
        const userId = req.user._id;
        const folder = req.body.folder || 'general';
        
        const uploadResult = handleFileUpload(req.file, folder, userId);
        
        res.json(formatResponse(true, 'File uploaded successfully', {
            fileUrl: uploadResult.url,
            fileName: uploadResult.filename,
            originalName: uploadResult.originalName,
            size: uploadResult.size,
            mimeType: uploadResult.mimeType,
            folder,
            uploadedAt: new Date()
        }));
    } catch (error) {
        handleError(res, error, 'Error uploading file');
    }
});

// ==================== PAYMENT WEBHOOKS ====================
if (config.paymentEnabled) {
    app.post('/api/webhooks/flutterwave', async (req, res) => {
        try {
            const secretHash = process.env.FLUTTERWAVE_SECRET_HASH;
            const signature = req.headers['verif-hash'];
            
            if (!signature || signature !== secretHash) {
                return res.status(401).send('Unauthorized');
            }
            
            const payload = req.body;
            
            if (payload.event === 'charge.completed' && payload.data.status === 'successful') {
                const { tx_ref, amount, customer } = payload.data;
                
                const deposit = await Deposit.findOne({ reference: tx_ref });
                if (!deposit) {
                    return res.status(404).send('Deposit not found');
                }
                
                deposit.status = 'approved';
                deposit.approved_at = new Date();
                deposit.transaction_hash = payload.data.flw_ref;
                await deposit.save();
                
                await createTransaction(
                    deposit.user,
                    'deposit',
                    amount,
                    `Deposit via Flutterwave`,
                    'completed',
                    {
                        deposit_id: deposit._id,
                        transaction_ref: tx_ref
                    }
                );
                
                await createNotification(
                    deposit.user,
                    'Deposit Successful',
                    `Your deposit of ₦${amount.toLocaleString()} has been approved and credited to your account.`,
                    'success',
                    '/deposits'
                );
                
                console.log(`✅ Flutterwave webhook: Deposit ${tx_ref} approved for ${amount}`);
            }
            
            res.status(200).send('Webhook processed');
        } catch (error) {
            console.error('Flutterwave webhook error:', error);
            res.status(500).send('Internal server error');
        }
    });
}

// ==================== ADVANCED DAILY INTEREST CRON JOB ====================
cron.schedule('0 * * * *', async () => {
    console.log('🔄 Running advanced daily interest calculation...');
    await calculateDailyInterest();
});

cron.schedule('*/5 * * * *', async () => {
    console.log('⏰ Quick check for investments needing interest...');
    
    try {
        const now = new Date();
        const activeInvestments = await Investment.find({
            status: 'active',
            end_date: { $gt: now },
            next_interest_date: { $lte: now }
        }).countDocuments();
        
        if (activeInvestments > 0) {
            console.log(`💰 ${activeInvestments} investments need interest, triggering calculation...`);
            await calculateDailyInterest();
        }
    } catch (error) {
        console.error('Quick check error:', error);
    }
});

cron.schedule('30 * * * *', async () => {
    if (config.cronLocks.investmentCompletion) {
        console.log('⏳ Investment completion cron already running, skipping...');
        return;
    }
    
    config.cronLocks.investmentCompletion = true;
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
    } finally {
        config.cronLocks.investmentCompletion = false;
    }
});

// ==================== ADMIN ENDPOINTS - ENHANCED WITH TWO-BALANCE SUPPORT ====================
app.get('/api/admin/dashboard', adminAuth, async (req, res) => {
    try {
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
            pendingKYC,
            amlFlags
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
            KYCSubmission.countDocuments({ status: 'pending' }),
            AmlMonitoring.countDocuments({ status: 'pending_review' })
        ]);
        
        const earningsResult = await Investment.aggregate([
            { $match: { status: 'active' } },
            { $group: { _id: null, total: { $sum: '$earned_so_far' } } }
        ]);
        
        const totalEarnings = earningsResult[0]?.total || 0;
        
        const userFinancials = await User.aggregate([
            { $match: { role: { $ne: 'super_admin' } } },
            { $group: {
                _id: null,
                total_balance: { $sum: '$balance' },
                total_principal: { $sum: '$principal_balance' },
                total_earnings_balance: { $sum: '$earnings_balance' },
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
            total_principal: 0,
            total_earnings_balance: 0,
            total_earnings: 0,
            total_referral_earnings: 0,
            total_withdrawn: 0,
            total_deposits: 0,
            total_withdrawals: 0,
            total_investments: 0
        };
        
        const totalPortfolio = financialSummary.total_balance || 0;
        
        const accountStatusStats = await User.aggregate([
            { $match: { role: { $ne: 'super_admin' } } },
            { $group: {
                _id: '$account_status',
                count: { $sum: 1 }
            } }
        ]);
        
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
            user_financials: {
                total_user_balance: financialSummary.total_balance,
                total_user_principal: financialSummary.total_principal,
                total_user_earnings_balance: financialSummary.total_earnings_balance,
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
            },
            account_status: accountStatusStats.reduce((acc, stat) => {
                acc[stat._id] = stat.count;
                return acc;
            }, {})
        };
        
        res.json(formatResponse(true, 'Admin dashboard stats retrieved successfully', {
            stats,
            quick_links: {
                pending_investments: '/api/admin/pending-investments',
                pending_deposits: '/api/admin/pending-deposits',
                pending_withdrawals: '/api/admin/pending-withdrawals',
                pending_kyc: '/api/admin/pending-kyc',
                aml_flags: '/api/admin/aml-flags',
                all_users: '/api/admin/users',
                suspended_users: '/api/admin/users?account_status=suspended',
                rejected_users: '/api/admin/users?account_status=rejected'
            }
        }));
    } catch (error) {
        handleError(res, error, 'Error fetching admin dashboard stats');
    }
});

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
        
        const enhancedUsers = users.map(user => ({
            ...user,
            portfolio_value: user.balance || 0,
            available_for_withdrawal: user.earnings_balance || 0,
            financial_summary: {
                balance: user.balance || 0,
                principal_balance: user.principal_balance || 0,
                earnings_balance: user.earnings_balance || 0,
                total_earnings: user.total_earnings || 0,
                referral_earnings: user.referral_earnings || 0,
                total_withdrawn: user.total_withdrawn || 0,
                total_deposits: user.total_deposits || 0,
                total_withdrawals: user.total_withdrawals || 0,
                total_investments: user.total_investments || 0
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
                active_users: enhancedUsers.filter(u => u.is_active).length,
                suspended_users: enhancedUsers.filter(u => u.account_status === 'suspended').length,
                rejected_users: enhancedUsers.filter(u => u.account_status === 'rejected').length,
                verified_users: enhancedUsers.filter(u => u.kyc_verified).length,
                total_balance: enhancedUsers.reduce((sum, u) => sum + (u.balance || 0), 0),
                total_principal: enhancedUsers.reduce((sum, u) => sum + (u.principal_balance || 0), 0),
                total_earnings_balance: enhancedUsers.reduce((sum, u) => sum + (u.earnings_balance || 0), 0),
                total_earnings: enhancedUsers.reduce((sum, u) => sum + (u.total_earnings || 0), 0),
                total_referral_earnings: enhancedUsers.reduce((sum, u) => sum + (u.referral_earnings || 0), 0),
                total_withdrawn: enhancedUsers.reduce((sum, u) => sum + (u.total_withdrawn || 0), 0),
                total_withdrawable: enhancedUsers.reduce((sum, u) => sum + (u.earnings_balance || 0), 0)
            }
        }));
    } catch (error) {
        handleError(res, error, 'Error fetching users');
    }
});

app.get('/api/admin/users/:id', adminAuth, async (req, res) => {
    try {
        const userId = req.params.id;
        
        const user = await User.findById(userId)
            .select('-password -two_factor_secret -verification_token -password_reset_token');
        
        if (!user) {
            return res.status(404).json(formatResponse(false, 'User not found'));
        }
        
        const [
            investments,
            deposits,
            withdrawals,
            referrals,
            transactions
        ] = await Promise.all([
            Investment.find({ user: userId })
                .populate('plan', 'name daily_interest duration')
                .sort({ createdAt: -1 })
                .lean(),
            Deposit.find({ user: userId })
                .sort({ createdAt: -1 })
                .lean(),
            Withdrawal.find({ user: userId })
                .sort({ createdAt: -1 })
                .lean(),
            Referral.find({ referrer: userId })
                .populate('referred_user', 'full_name email createdAt')
                .sort({ createdAt: -1 })
                .lean(),
            Transaction.find({ user: userId })
                .sort({ createdAt: -1 })
                .limit(50)
                .lean()
        ]);
        
        const financialSummary = {
            current_balance: user.balance || 0,
            principal_balance: user.principal_balance || 0,
            earnings_balance: user.earnings_balance || 0,
            total_earnings: user.total_earnings || 0,
            referral_earnings: user.referral_earnings || 0,
            total_withdrawn: user.total_withdrawn || 0,
            withdrawable_earnings: user.withdrawable_earnings || 0,
            total_deposits: user.total_deposits || 0,
            total_withdrawals: user.total_withdrawals || 0,
            total_investments: user.total_investments || 0,
            portfolio_value: user.balance || 0
        };
        
        const userDetails = {
            user: user.toObject(),
            financial_summary: financialSummary,
            stats: {
                total_investments: investments.length,
                total_deposits: deposits.length,
                total_withdrawals: withdrawals.length,
                total_referrals: referrals.length,
                total_transactions: transactions.length
            },
            preview: {
                investments: investments.slice(0, 5),
                deposits: deposits.slice(0, 5),
                withdrawals: withdrawals.slice(0, 5),
                referrals: referrals.slice(0, 5),
                transactions: transactions.slice(0, 10)
            }
        };
        
        res.json(formatResponse(true, 'User details retrieved successfully', userDetails));
    } catch (error) {
        console.error('Error fetching user details:', error);
        handleError(res, error, 'Error fetching user information');
    }
});

// ==================== ADVANCED ADMIN USER MANAGEMENT ENDPOINTS ====================
app.post('/api/admin/users/:id/suspend', adminAuth, [
    body('reason').notEmpty().trim().isLength({ min: 5, max: 500 }),
    body('duration_days').optional().isInt({ min: 1, max: 365 })
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
        
        if (user.role === 'super_admin') {
            return res.status(403).json(formatResponse(false, 'Cannot suspend super admin'));
        }
        
        if (user.role === 'admin' && req.user.role !== 'super_admin') {
            return res.status(403).json(formatResponse(false, 'Only super admin can suspend other admins'));
        }
        
        user.suspendAccount(reason, adminId, duration_days);
        await user.save();
        
        await AdminAudit.create({
            admin_id: adminId,
            action: 'suspend_user',
            target_type: 'user',
            target_id: userId,
            details: {
                reason,
                duration_days: duration_days || 'indefinite',
                user_email: user.email
            },
            ip_address: req.ip,
            user_agent: req.headers['user-agent']
        });
        
        await createNotification(
            userId,
            'Account Suspended',
            `Your account has been suspended. Reason: ${reason}${duration_days ? ` Duration: ${duration_days} days` : ''}. Please contact support for more information.`,
            'error',
            '/support'
        );
        
        emitToAdmins('user-suspended', {
            user_id: userId,
            user_email: user.email,
            suspended_by: adminId,
            reason,
            duration_days
        });
        
        res.json(formatResponse(true, 'User account suspended successfully', {
            user: {
                id: user._id,
                email: user.email,
                account_status: user.account_status,
                suspension_reason: user.suspension_reason,
                suspension_date: user.suspension_date,
                suspension_end_date: user.suspension_end_date
            }
        }));
    } catch (error) {
        handleError(res, error, 'Error suspending user account');
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
        
        if (user.account_status !== 'suspended') {
            return res.status(400).json(formatResponse(false, 'User account is not suspended'));
        }
        
        user.activateAccount();
        await user.save();
        
        await AdminAudit.create({
            admin_id: adminId,
            action: 'activate_user',
            target_type: 'user',
            target_id: userId,
            details: {
                user_email: user.email,
                previous_status: 'suspended'
            },
            ip_address: req.ip,
            user_agent: req.headers['user-agent']
        });
        
        await createNotification(
            userId,
            'Account Activated',
            'Your account has been activated. You can now access all features.',
            'success',
            '/dashboard'
        );
        
        emitToAdmins('user-activated', {
            user_id: userId,
            user_email: user.email,
            activated_by: adminId
        });
        
        res.json(formatResponse(true, 'User account activated successfully', {
            user: {
                id: user._id,
                email: user.email,
                account_status: user.account_status,
                is_active: user.is_active
            }
        }));
    } catch (error) {
        handleError(res, error, 'Error activating user account');
    }
});

app.post('/api/admin/users/:id/reject', adminAuth, [
    body('reason').notEmpty().trim().isLength({ min: 5, max: 500 })
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
        
        if (user.role === 'super_admin') {
            return res.status(403).json(formatResponse(false, 'Cannot reject super admin'));
        }
        
        if (user.role === 'admin' && req.user.role !== 'super_admin') {
            return res.status(403).json(formatResponse(false, 'Only super admin can reject other admins'));
        }
        
        user.rejectAccount(reason, adminId);
        await user.save();
        
        await AdminAudit.create({
            admin_id: adminId,
            action: 'reject_user',
            target_type: 'user',
            target_id: userId,
            details: {
                reason,
                user_email: user.email
            },
            ip_address: req.ip,
            user_agent: req.headers['user-agent']
        });
        
        await createNotification(
            userId,
            'Account Rejected',
            `Your account has been rejected. Reason: ${reason}. Please contact support for more information.`,
            'error',
            '/support'
        );
        
        emitToAdmins('user-rejected', {
            user_id: userId,
            user_email: user.email,
            rejected_by: adminId,
            reason
        });
        
        res.json(formatResponse(true, 'User account rejected successfully', {
            user: {
                id: user._id,
                email: user.email,
                account_status: user.account_status,
                suspension_reason: user.suspension_reason,
                suspension_date: user.suspension_date
            }
        }));
    } catch (error) {
        handleError(res, error, 'Error rejecting user account');
    }
});

app.post('/api/admin/users/:id/update-balance', adminAuth, [
    body('amount').isFloat(),
    body('type').isIn(['add', 'subtract', 'set']),
    body('reason').notEmpty().trim().isLength({ min: 5, max: 500 }),
    body('target_balance').optional().isIn(['principal', 'earnings', 'both'])
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json(formatResponse(false, 'Validation failed'));
        }
        
        const userId = req.params.id;
        const adminId = req.user._id;
        const { amount, type, reason, target_balance = 'principal' } = req.body;
        
        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json(formatResponse(false, 'User not found'));
        }
        
        let oldPrincipal = user.principal_balance;
        let oldEarnings = user.earnings_balance;
        let newPrincipal = oldPrincipal;
        let newEarnings = oldEarnings;
        let transactionAmount = 0;
        let transactionDescription = '';
        let targetType = target_balance;
        
        const numericAmount = parseFloat(amount);
        
        switch (type) {
            case 'add':
                if (targetType === 'principal') {
                    newPrincipal += numericAmount;
                } else if (targetType === 'earnings') {
                    newEarnings += numericAmount;
                } else {
                    // both
                    newPrincipal += numericAmount / 2;
                    newEarnings += numericAmount / 2;
                }
                transactionAmount = numericAmount;
                transactionDescription = `Admin added to ${targetType} balance: ${reason}`;
                break;
            case 'subtract':
                if (targetType === 'principal') {
                    newPrincipal = Math.max(0, oldPrincipal - numericAmount);
                } else if (targetType === 'earnings') {
                    newEarnings = Math.max(0, oldEarnings - numericAmount);
                } else {
                    // both: subtract proportionally
                    let total = oldPrincipal + oldEarnings;
                    if (total > 0) {
                        let ratioPrincipal = oldPrincipal / total;
                        let ratioEarnings = oldEarnings / total;
                        newPrincipal = Math.max(0, oldPrincipal - numericAmount * ratioPrincipal);
                        newEarnings = Math.max(0, oldEarnings - numericAmount * ratioEarnings);
                    }
                }
                transactionAmount = -numericAmount;
                transactionDescription = `Admin deducted from ${targetType} balance: ${reason}`;
                break;
            case 'set':
                if (targetType === 'principal') {
                    newPrincipal = numericAmount;
                } else if (targetType === 'earnings') {
                    newEarnings = numericAmount;
                } else {
                    // set both to specific values? not supported, default to principal
                    newPrincipal = numericAmount;
                }
                transactionAmount = (newPrincipal - oldPrincipal) + (newEarnings - oldEarnings);
                transactionDescription = `Admin set ${targetType} balance: ${reason}`;
                break;
        }
        
        user.principal_balance = newPrincipal;
        user.earnings_balance = newEarnings;
        // Balance will auto-update via pre-save
        await user.save();
        
        if (transactionAmount !== 0) {
            await createTransaction(
                userId,
                'bonus',
                transactionAmount,
                transactionDescription,
                'completed',
                {
                    admin_id: adminId,
                    reason,
                    principal_before: oldPrincipal,
                    principal_after: newPrincipal,
                    earnings_before: oldEarnings,
                    earnings_after: newEarnings,
                    balance_before: oldPrincipal + oldEarnings,
                    balance_after: newPrincipal + newEarnings,
                    admin_action: true
                }
            );
        }
        
        await AdminAudit.create({
            admin_id: adminId,
            action: 'update_balance',
            target_type: 'user',
            target_id: userId,
            details: {
                amount: numericAmount,
                type,
                target_balance: targetType,
                reason,
                old_principal: oldPrincipal,
                new_principal: newPrincipal,
                old_earnings: oldEarnings,
                new_earnings: newEarnings,
                user_email: user.email
            },
            ip_address: req.ip,
            user_agent: req.headers['user-agent']
        });
        
        await createNotification(
            userId,
            'Balance Updated',
            `Your balance has been updated by admin. New principal: ₦${newPrincipal.toLocaleString()}, Earnings: ₦${newEarnings.toLocaleString()}. Reason: ${reason}`,
            'info',
            '/profile'
        );
        
        res.json(formatResponse(true, 'User balance updated successfully', {
            user: {
                id: user._id,
                email: user.email,
                old_principal: oldPrincipal,
                new_principal: newPrincipal,
                old_earnings: oldEarnings,
                new_earnings: newEarnings,
                transaction_amount: transactionAmount
            }
        }));
    } catch (error) {
        handleError(res, error, 'Error updating user balance');
    }
});

// ==================== ADMIN INVESTMENT MANAGEMENT ====================
app.get('/api/admin/pending-investments', adminAuth, async (req, res) => {
    try {
        const pendingInvestments = await Investment.find({ status: 'pending' })
            .populate('user', 'full_name email phone balance principal_balance earnings_balance')
            .populate('plan', 'name min_amount daily_interest duration')
            .sort({ createdAt: -1 })
            .lean();
        
        res.json(formatResponse(true, 'Pending investments retrieved successfully', {
            investments: pendingInvestments,
            count: pendingInvestments.length,
            total_amount: pendingInvestments.reduce((sum, inv) => sum + inv.amount, 0),
            stats: {
                with_proof: pendingInvestments.filter(inv => inv.payment_proof_url).length,
                without_proof: pendingInvestments.filter(inv => !inv.payment_proof_url).length,
                average_amount: pendingInvestments.length > 0 ? 
                    pendingInvestments.reduce((sum, inv) => sum + inv.amount, 0) / pendingInvestments.length : 0
            }
        }));
    } catch (error) {
        handleError(res, error, 'Error fetching pending investments');
    }
});

app.post('/api/admin/investments/:id/approve', adminAuth, [
    body('remarks').optional().trim()
], async (req, res) => {
    try {
        const investmentId = req.params.id;
        const adminId = req.user._id;
        const { remarks } = req.body;
        
        const investment = await Investment.findById(investmentId)
            .populate('plan')
            .populate('user');
        
        if (!investment) {
            return res.status(404).json(formatResponse(false, 'Investment not found'));
        }
        
        if (investment.status !== 'pending') {
            return res.status(400).json(formatResponse(false, 'Investment is not pending approval'));
        }
        
        const user = await User.findById(investment.user._id);
        if (investment.amount > user.principal_balance) {
            return res.status(400).json(formatResponse(false,
                `User does not have enough principal balance for this investment. Required: ${investment.amount}, Available principal: ${user.principal_balance}`));
        }
        
        const txResult = await createTransaction(
            investment.user._id,
            'investment',
            -investment.amount,
            `Investment in ${investment.plan.name} plan (admin approved)`,
            'completed',
            {
                investment_id: investment._id,
                plan_name: investment.plan.name,
                plan_duration: investment.plan.duration,
                daily_interest: investment.plan.daily_interest,
                admin_approved: true
            }
        );
        
        if (!txResult.success) {
            throw new Error('Investment transaction failed');
        }
        
        const nextInterestDate = new Date(Date.now() + 24 * 60 * 60 * 1000);
        
        investment.status = 'active';
        investment.approved_at = new Date();
        investment.approved_by = adminId;
        investment.payment_verified = true;
        investment.remarks = remarks;
        investment.next_interest_date = nextInterestDate;
        investment.total_interest_days = investment.plan.duration;
        investment.balance_deducted = true;
        
        await investment.save();
        
        await InvestmentPlan.findByIdAndUpdate(investment.plan._id, {
            $inc: {
                investment_count: 1,
                total_invested: investment.amount
            }
        });
        
        const addInterestResult = await addFirstDayInterest(investment);
        
        await createNotification(
            investment.user._id,
            'Investment Approved',
            `Your investment of ₦${investment.amount.toLocaleString()} in ${investment.plan.name} has been approved and is now active. First interest of ₦${addInterestResult.dailyEarning?.toLocaleString() || '0'} has been credited to your earnings balance.`,
            'investment',
            '/investments'
        );
        
        await AdminAudit.create({
            admin_id: adminId,
            action: 'approve_investment',
            target_type: 'investment',
            target_id: investmentId,
            details: {
                investment_amount: investment.amount,
                plan_name: investment.plan.name,
                user_email: investment.user.email,
                daily_interest_added: addInterestResult.dailyEarning,
                next_interest_date: investment.next_interest_date
            },
            ip_address: req.ip,
            user_agent: req.headers['user-agent']
        });
        
        emitToAdmins('investment-approved', {
            investment_id: investmentId,
            user_id: investment.user._id,
            amount: investment.amount,
            plan_name: investment.plan.name,
            approved_by: adminId
        });
        
        res.json(formatResponse(true, 'Investment approved successfully', {
            investment: investment.toObject(),
            interest_added: addInterestResult.success,
            daily_interest: addInterestResult.dailyEarning,
            next_interest_date: investment.next_interest_date
        }));
    } catch (error) {
        handleError(res, error, 'Error approving investment');
    }
});

app.post('/api/admin/investments/:id/reject', adminAuth, [
    body('rejection_reason').notEmpty().trim().isLength({ min: 5, max: 500 })
], async (req, res) => {
    const session = await mongoose.startSession();
    session.startTransaction();
    
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            await session.abortTransaction();
            session.endSession();
            return res.status(400).json(formatResponse(false, 'Validation failed'));
        }
        
        const investmentId = req.params.id;
        const adminId = req.user._id;
        const { rejection_reason } = req.body;
        
        const investment = await Investment.findById(investmentId)
            .populate('plan')
            .populate('user')
            .session(session);
        
        if (!investment) {
            await session.abortTransaction();
            session.endSession();
            return res.status(404).json(formatResponse(false, 'Investment not found'));
        }
        
        if (investment.status !== 'active' && investment.status !== 'pending') {
            await session.abortTransaction();
            session.endSession();
            return res.status(400).json(formatResponse(false, 'Investment cannot be rejected in its current state'));
        }
        
        if (investment.status === 'active' && investment.balance_deducted) {
            const user = await User.findById(investment.user._id).session(session);
            
            // Reverse the deducted amount back to principal_balance
            user.principal_balance += investment.amount;
            
            if (investment.earned_so_far > 0) {
                // Remove any interest already earned from earnings_balance and total_earnings
                user.earnings_balance = Math.max(0, user.earnings_balance - investment.earned_so_far);
                user.total_earnings = Math.max(0, user.total_earnings - investment.earned_so_far);
                // Balance auto-updates
            }
            
            await user.save({ session });
            
            const refundTransaction = new Transaction({
                user: investment.user._id,
                type: 'refund',
                amount: investment.amount,
                description: `Refund for rejected investment in ${investment.plan.name} (${rejection_reason})`,
                status: 'completed',
                reference: generateReference('REF'),
                balance_before: user.balance - investment.amount,
                balance_after: user.balance,
                principal_before: user.principal_balance - investment.amount,
                principal_after: user.principal_balance,
                earnings_before: user.earnings_balance + (investment.earned_so_far || 0),
                earnings_after: user.earnings_balance,
                related_investment: investment._id,
                metadata: {
                    rejected_by: adminId,
                    rejection_reason,
                    interest_earned_reversed: investment.earned_so_far
                }
            });
            await refundTransaction.save({ session });
            
            investment.reversal_transaction_id = refundTransaction._id;
            investment.reversed_at = new Date();
        }
        
        investment.status = 'rejected';
        investment.rejected_at = new Date();
        investment.rejected_by = adminId;
        investment.rejection_reason = rejection_reason;
        
        await investment.save({ session });
        
        await AdminAudit.create([{
            admin_id: adminId,
            action: 'reject_investment',
            target_type: 'investment',
            target_id: investmentId,
            details: {
                investment_amount: investment.amount,
                plan_name: investment.plan.name,
                user_email: investment.user.email,
                rejection_reason,
                reversal_applied: investment.balance_deducted
            },
            ip_address: req.ip,
            user_agent: req.headers['user-agent']
        }], { session });
        
        await session.commitTransaction();
        session.endSession();
        
        await createNotification(
            investment.user._id,
            'Investment Rejected',
            `Your investment of ₦${investment.amount.toLocaleString()} in ${investment.plan.name} has been rejected. Reason: ${rejection_reason}.${investment.balance_deducted ? ' The invested amount has been refunded to your principal balance.' : ''}`,
            'error',
            '/investments'
        );
        
        emitToAdmins('investment-rejected', {
            investment_id: investmentId,
            user_id: investment.user._id,
            amount: investment.amount,
            plan_name: investment.plan.name,
            rejected_by: adminId,
            rejection_reason,
            refunded: investment.balance_deducted
        });
        
        res.json(formatResponse(true, 'Investment rejected successfully' + (investment.balance_deducted ? ' and amount refunded' : ''), {
            investment: investment.toObject()
        }));
    } catch (error) {
        await session.abortTransaction();
        session.endSession();
        handleError(res, error, 'Error rejecting investment');
    }
});

// ==================== ADVANCED DEPOSIT MANAGEMENT ====================
app.get('/api/admin/pending-deposits', adminAuth, async (req, res) => {
    try {
        const pendingDeposits = await Deposit.find({ status: 'pending' })
            .populate('user', 'full_name email phone balance principal_balance earnings_balance')
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
        
        deposit.status = 'approved';
        deposit.approved_at = new Date();
        deposit.approved_by = adminId;
        deposit.admin_notes = remarks;
        
        await deposit.save();
        
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
        
        await createNotification(
            deposit.user._id,
            'Deposit Approved',
            `Your deposit of ₦${deposit.amount.toLocaleString()} has been approved and credited to your principal balance.`,
            'success',
            '/deposits'
        );
        
        await AdminAudit.create({
            admin_id: adminId,
            action: 'approve_deposit',
            target_type: 'deposit',
            target_id: depositId,
            details: {
                deposit_amount: deposit.amount,
                payment_method: deposit.payment_method,
                user_email: deposit.user.email
            },
            ip_address: req.ip,
            user_agent: req.headers['user-agent']
        });
        
        emitToAdmins('deposit-approved', {
            deposit_id: depositId,
            user_id: deposit.user._id,
            amount: deposit.amount,
            payment_method: deposit.payment_method,
            approved_by: adminId
        });
        
        res.json(formatResponse(true, 'Deposit approved successfully', {
            deposit: deposit.toObject()
        }));
    } catch (error) {
        handleError(res, error, 'Error approving deposit');
    }
});

app.post('/api/admin/deposits/:id/reject', adminAuth, [
    body('rejection_reason').notEmpty().trim().isLength({ min: 5, max: 500 })
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json(formatResponse(false, 'Validation failed'));
        }
        
        const depositId = req.params.id;
        const adminId = req.user._id;
        const { rejection_reason } = req.body;
        
        const deposit = await Deposit.findById(depositId)
            .populate('user');
        
        if (!deposit) {
            return res.status(404).json(formatResponse(false, 'Deposit not found'));
        }
        
        if (deposit.status !== 'pending') {
            return res.status(400).json(formatResponse(false, 'Deposit is not pending'));
        }
        
        deposit.status = 'rejected';
        deposit.rejected_at = new Date();
        deposit.rejected_by = adminId;
        deposit.rejection_reason = rejection_reason;
        
        await deposit.save();
        
        await AdminAudit.create({
            admin_id: adminId,
            action: 'reject_deposit',
            target_type: 'deposit',
            target_id: depositId,
            details: {
                deposit_amount: deposit.amount,
                payment_method: deposit.payment_method,
                user_email: deposit.user.email,
                rejection_reason
            },
            ip_address: req.ip,
            user_agent: req.headers['user-agent']
        });
        
        await createNotification(
            deposit.user._id,
            'Deposit Rejected',
            `Your deposit request of ₦${deposit.amount.toLocaleString()} has been rejected. Reason: ${rejection_reason}. Please contact support for more information.`,
            'error',
            '/deposits'
        );
        
        emitToAdmins('deposit-rejected', {
            deposit_id: depositId,
            user_id: deposit.user._id,
            amount: deposit.amount,
            payment_method: deposit.payment_method,
            rejected_by: adminId,
            rejection_reason
        });
        
        res.json(formatResponse(true, 'Deposit rejected successfully', {
            deposit: deposit.toObject()
        }));
    } catch (error) {
        handleError(res, error, 'Error rejecting deposit');
    }
});

// ==================== ADVANCED WITHDRAWAL MANAGEMENT ====================
app.get('/api/admin/pending-withdrawals', adminAuth, async (req, res) => {
    try {
        const pendingWithdrawals = await Withdrawal.find({ 
            status: 'pending',
            admin_review_status: 'pending_review'
        })
            .populate('user', 'full_name email phone balance principal_balance earnings_balance total_earnings total_withdrawn')
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

app.post('/api/admin/withdrawals/:id/approve', adminAuth, [
    body('transaction_id').optional().trim(),
    body('remarks').optional().trim()
], async (req, res) => {
    const session = await mongoose.startSession();
    session.startTransaction();
    
    try {
        const withdrawalId = req.params.id;
        const adminId = req.user._id;
        const { transaction_id, remarks } = req.body;
        
        const withdrawal = await Withdrawal.findById(withdrawalId)
            .populate('user')
            .session(session);
        
        if (!withdrawal) {
            await session.abortTransaction();
            session.endSession();
            return res.status(404).json(formatResponse(false, 'Withdrawal not found'));
        }
        
        if (withdrawal.status !== 'pending') {
            await session.abortTransaction();
            session.endSession();
            return res.status(400).json(formatResponse(false, 'Withdrawal is not pending approval'));
        }
        
        const user = await User.findById(withdrawal.user._id).session(session);
        if (withdrawal.amount > user.earnings_balance) {
            await session.abortTransaction();
            session.endSession();
            return res.status(400).json(formatResponse(false,
                `User does not have enough earnings to withdraw ${withdrawal.amount}. Available earnings: ${user.earnings_balance}`));
        }
        
        withdrawal.status = 'paid';
        withdrawal.approved_at = new Date();
        withdrawal.approved_by = adminId;
        withdrawal.paid_at = new Date();
        withdrawal.transaction_id = transaction_id;
        withdrawal.admin_notes = remarks;
        withdrawal.admin_review_status = 'approved';
        withdrawal.reviewed_by = adminId;
        withdrawal.review_date = new Date();
        
        await withdrawal.save({ session });
        
        const pendingTransaction = await Transaction.findById(withdrawal.transaction_id_ref).session(session);
        if (pendingTransaction) {
            pendingTransaction.status = 'completed';
            pendingTransaction.description = `Withdrawal via ${withdrawal.payment_method}`;
            await pendingTransaction.save({ session });
        } else {
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
                    transaction_id: transaction_id,
                    from_earnings: withdrawal.amount,
                    from_principal: 0
                }
            );
        }
        
        // Update user's earnings_balance and total_withdrawn
        user.earnings_balance -= withdrawal.amount;
        user.total_withdrawn += withdrawal.amount;
        user.total_withdrawals = (user.total_withdrawals || 0) + withdrawal.amount;
        user.last_withdrawal_date = new Date();
        await user.save({ session });
        
        await session.commitTransaction();
        session.endSession();
        
        await createNotification(
            withdrawal.user._id,
            'Withdrawal Approved',
            `Your withdrawal of ₦${withdrawal.amount.toLocaleString()} has been approved and processed.`,
            'success',
            '/withdrawals'
        );
        
        await AdminAudit.create({
            admin_id: adminId,
            action: 'approve_withdrawal',
            target_type: 'withdrawal',
            target_id: withdrawalId,
            details: {
                withdrawal_amount: withdrawal.amount,
                payment_method: withdrawal.payment_method,
                user_email: withdrawal.user.email,
                transaction_id
            },
            ip_address: req.ip,
            user_agent: req.headers['user-agent']
        });
        
        emitToAdmins('withdrawal-approved', {
            withdrawal_id: withdrawalId,
            user_id: withdrawal.user._id,
            amount: withdrawal.amount,
            payment_method: withdrawal.payment_method,
            approved_by: adminId
        });
        
        res.json(formatResponse(true, 'Withdrawal approved successfully', {
            withdrawal: withdrawal.toObject()
        }));
    } catch (error) {
        await session.abortTransaction();
        session.endSession();
        handleError(res, error, 'Error approving withdrawal');
    }
});

app.post('/api/admin/withdrawals/:id/reject', adminAuth, [
    body('rejection_reason').notEmpty().trim()
], async (req, res) => {
    const session = await mongoose.startSession();
    session.startTransaction();
    
    try {
        const withdrawalId = req.params.id;
        const adminId = req.user._id;
        const { rejection_reason } = req.body;
        
        const withdrawal = await Withdrawal.findById(withdrawalId)
            .populate('user')
            .session(session);
        
        if (!withdrawal) {
            await session.abortTransaction();
            session.endSession();
            return res.status(404).json(formatResponse(false, 'Withdrawal not found'));
        }
        
        if (withdrawal.status !== 'pending') {
            await session.abortTransaction();
            session.endSession();
            return res.status(400).json(formatResponse(false, 'Withdrawal is not pending'));
        }
        
        withdrawal.status = 'rejected';
        withdrawal.admin_review_status = 'rejected';
        withdrawal.reviewed_by = adminId;
        withdrawal.review_date = new Date();
        withdrawal.review_notes = rejection_reason;
        
        await withdrawal.save({ session });
        
        const pendingTransaction = await Transaction.findById(withdrawal.transaction_id_ref).session(session);
        if (pendingTransaction) {
            pendingTransaction.status = 'cancelled';
            pendingTransaction.description = `Withdrawal rejected: ${rejection_reason}`;
            await pendingTransaction.save({ session });
        }
        
        await session.commitTransaction();
        session.endSession();
        
        await createNotification(
            withdrawal.user._id,
            'Withdrawal Rejected',
            `Your withdrawal request of ₦${withdrawal.amount.toLocaleString()} has been rejected. Reason: ${rejection_reason}`,
            'error',
            '/withdrawals'
        );
        
        await AdminAudit.create({
            admin_id: adminId,
            action: 'reject_withdrawal',
            target_type: 'withdrawal',
            target_id: withdrawalId,
            details: {
                withdrawal_amount: withdrawal.amount,
                payment_method: withdrawal.payment_method,
                user_email: withdrawal.user.email,
                rejection_reason
            },
            ip_address: req.ip,
            user_agent: req.headers['user-agent']
        });
        
        emitToAdmins('withdrawal-rejected', {
            withdrawal_id: withdrawalId,
            user_id: withdrawal.user._id,
            amount: withdrawal.amount,
            payment_method: withdrawal.payment_method,
            rejected_by: adminId,
            rejection_reason
        });
        
        res.json(formatResponse(true, 'Withdrawal rejected successfully', {
            withdrawal: withdrawal.toObject()
        }));
    } catch (error) {
        await session.abortTransaction();
        session.endSession();
        handleError(res, error, 'Error rejecting withdrawal');
    }
});

// ==================== ADVANCED KYC MANAGEMENT ====================
app.get('/api/admin/pending-kyc', adminAuth, async (req, res) => {
    try {
        const pendingKYC = await KYCSubmission.find({ status: 'pending' })
            .populate('user', 'full_name email phone balance principal_balance earnings_balance')
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
        
        kyc.status = 'approved';
        kyc.reviewed_by = adminId;
        kyc.reviewed_at = new Date();
        kyc.notes = remarks;
        
        await kyc.save();
        
        await User.findByIdAndUpdate(kyc.user._id, {
            kyc_status: 'verified',
            kyc_verified: true,
            kyc_verified_at: new Date(),
            'bank_details.verified': true,
            'bank_details.verified_at': new Date()
        });
        
        await createNotification(
            kyc.user._id,
            'KYC Approved',
            'Your KYC documents have been verified and approved. You can now enjoy full platform access.',
            'kyc',
            '/profile'
        );
        
        await AdminAudit.create({
            admin_id: adminId,
            action: 'approve_kyc',
            target_type: 'kyc',
            target_id: kycId,
            details: {
                user_email: kyc.user.email,
                id_type: kyc.id_type
            },
            ip_address: req.ip,
            user_agent: req.headers['user-agent']
        });
        
        emitToAdmins('kyc-approved', {
            kyc_id: kycId,
            user_id: kyc.user._id,
            approved_by: adminId
        });
        
        res.json(formatResponse(true, 'KYC approved successfully', {
            kyc: kyc.toObject()
        }));
    } catch (error) {
        handleError(res, error, 'Error approving KYC');
    }
});

// ==================== ADVANCED AML MANAGEMENT ====================
app.get('/api/admin/aml-flags', adminAuth, async (req, res) => {
    try {
        const amlFlags = await AmlMonitoring.find({ status: 'pending_review' })
            .populate('user', 'full_name email balance principal_balance earnings_balance')
            .sort({ risk_score: -1, createdAt: -1 })
            .lean();
        
        res.json(formatResponse(true, 'AML flags retrieved successfully', {
            flags: amlFlags,
            count: amlFlags.length
        }));
    } catch (error) {
        handleError(res, error, 'Error fetching AML flags');
    }
});

// ==================== ENHANCED ADMIN FINANCIAL REPORTS ENDPOINT ====================
app.get('/api/admin/financial-report', adminAuth, async (req, res) => {
    try {
        const { start_date, end_date, group_by = 'day' } = req.query;
        
        const matchStage = {};
        if (start_date || end_date) {
            matchStage.createdAt = {};
            if (start_date) matchStage.createdAt.$gte = new Date(start_date);
            if (end_date) matchStage.createdAt.$lte = new Date(end_date);
        }
        
        const userFinancials = await User.aggregate([
            { $match: { role: { $ne: 'super_admin' } } },
            { $group: {
                _id: null,
                total_balance: { $sum: '$balance' },
                total_principal: { $sum: '$principal_balance' },
                total_earnings_balance: { $sum: '$earnings_balance' },
                total_earnings: { $sum: '$total_earnings' },
                total_referral_earnings: { $sum: '$referral_earnings' },
                total_withdrawn: { $sum: '$total_withdrawn' },
                total_deposits: { $sum: '$total_deposits' },
                total_withdrawals: { $sum: '$total_withdrawals' },
                total_investments: { $sum: '$total_investments' },
                user_count: { $sum: 1 },
                active_users: { $sum: { $cond: [{ $eq: ['$is_active', true] }, 1, 0] } },
                verified_users: { $sum: { $cond: [{ $eq: ['$kyc_verified', true] }, 1, 0] } }
            } }
        ]);
        
        const transactionStats = await Transaction.aggregate([
            { $match: matchStage },
            { $group: {
                _id: '$type',
                count: { $sum: 1 },
                total_amount: { $sum: '$amount' }
            } }
        ]);
        
        const depositStats = await Deposit.aggregate([
            { $match: { ...matchStage, status: 'approved' } },
            { $group: {
                _id: null,
                count: { $sum: 1 },
                total_amount: { $sum: '$amount' },
                avg_amount: { $avg: '$amount' }
            } }
        ]);
        
        const withdrawalStats = await Withdrawal.aggregate([
            { $match: { ...matchStage, status: 'paid' } },
            { $group: {
                _id: null,
                count: { $sum: 1 },
                total_amount: { $sum: '$amount' },
                total_fees: { $sum: '$platform_fee' },
                avg_amount: { $avg: '$amount' }
            } }
        ]);
        
        const investmentStats = await Investment.aggregate([
            { $match: matchStage },
            { $group: {
                _id: '$status',
                count: { $sum: 1 },
                total_amount: { $sum: '$amount' },
                total_earned: { $sum: '$earned_so_far' }
            } }
        ]);
        
        res.json(formatResponse(true, 'Financial report generated successfully', {
            user_financials: userFinancials[0] || {},
            transaction_summary: transactionStats,
            deposit_summary: depositStats[0] || {},
            withdrawal_summary: withdrawalStats[0] || {},
            investment_summary: investmentStats,
            date_range: {
                start_date: start_date || 'Beginning',
                end_date: end_date || 'Now'
            }
        }));
    } catch (error) {
        console.error('Financial report error:', error);
        handleError(res, error, 'Error generating financial report');
    }
});

// ==================== 🚨 TEMPORARY: FORCE ADMIN CREATION – REMOVE AFTER USE! ====================
app.get('/api/debug/force-admin', async (req, res) => {
    try {
        const adminEmail = process.env.ADMIN_EMAIL || "admin@rawwealthy.com";
        const adminPassword = process.env.ADMIN_PASSWORD || "Admin123456";
        const adminName = "Super Admin";

        let admin = await User.findOne({ email: adminEmail });

        if (admin) {
            // Update existing admin
            admin.password = adminPassword;      // Will be hashed on save
            admin.full_name = adminName;
            admin.role = "super_admin";
            admin.is_active = true;
            admin.account_status = "active";
            await admin.save();
            res.send(`✅ Admin updated. Email: ${adminEmail}, Password: ${adminPassword}`);
        } else {
            // Create new admin
            admin = new User({
                full_name: adminName,
                email: adminEmail,
                phone: "0000000000",
                password: adminPassword,
                role: "super_admin",
                balance: 1000000,
                principal_balance: 1000000,
                earnings_balance: 0,
                kyc_verified: true,
                is_active: true,
                account_status: "active",
                email_notifications: true
            });
            await admin.save();
            res.send(`✅ Admin created. Email: ${adminEmail}, Password: ${adminPassword}`);
        }
    } catch (error) {
        res.status(500).send(`❌ Error: ${error.message}`);
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
            console.log(`✅ Raw Wealthy Backend v52.0 - TWO-BALANCE SYSTEM`);
            console.log(`🌐 Environment: ${config.nodeEnv}`);
            console.log(`📍 Port: ${config.port}`);
            console.log(`🔗 Server URL: ${config.serverURL}`);
            console.log(`🔗 Client URL: ${config.clientURL}`);
            console.log(`🔌 Socket.IO: Enabled with JWT Authentication`);
            console.log(`📊 Database: Connected`);
            console.log('============================================\n');
            
            console.log('🎯 TWO-BALANCE SYSTEM ACTIVATED:');
            console.log('1. ✅ PRINCIPAL BALANCE: Money from deposits (can be reinvested)');
            console.log('2. ✅ EARNINGS BALANCE: Money from interest/referrals (withdrawable only)');
            console.log('3. ✅ REINVESTMENT only from principal balance');
            console.log('4. ✅ WITHDRAWAL only from earnings balance');
            console.log('5. ✅ First day interest immediately credited to earnings');
            console.log('6. ✅ Existing users migrated with principal = total balance');
            console.log('============================================\n');
            
            console.log('💰 UPDATED INTEREST RATES & DURATIONS:');
            console.log('============================================');
            console.log(`FIRST THREE PLANS (${config.planDurations.firstThree} days):`);
            console.log('1. 🌱 Cocoa Beans: ₦3,500 min (15% daily)');
            console.log('2. 🥇 Gold: ₦50,000 min (20% daily)');
            console.log('3. 🛢️ Crude Oil: ₦100,000 min (25% daily)');
            console.log(`\nNEXT THREE PLANS (${config.planDurations.nextThree} days):`);
            console.log('4. ☕ Coffee Beans: ₦5,500 min (19% daily)');
            console.log('5. 🥈 Silver Bullion: ₦15,000 min (17% daily)');
            console.log('6. 🌳 Timber (Teak): ₦20,000 min (19% daily)');
            console.log(`\nREMAINING PLANS (${config.planDurations.remaining} days):`);
            console.log('7. 🔥 Natural Gas: ₦75,000 min (23% daily)');
            console.log('8. 🐟 Aquaculture (Salmon): ₦30,000 min (21% daily)');
            console.log(`📊 Total Investment Plans: 8`);
            console.log(`💰 Price Range: ₦3,500 - ₦1,000,000`);
            console.log(`💰 Minimum Withdrawal: ₦${config.minWithdrawal.toLocaleString()}`);
            console.log(`💰 Referral Commission: ${config.referralCommissionPercent}% (First investment only)`);
            console.log('============================================\n');
            
            console.log('👨‍💼 ENHANCED ADMIN FEATURES:');
            console.log('1. ✅ PRINCIPAL/EARNINGS breakdown in user lists');
            console.log('2. ✅ BALANCE UPDATE with target selection (principal/earnings)');
            console.log('3. ✅ INVESTMENT REVERSAL with earnings refund');
            console.log('4. ✅ WITHDRAWAL APPROVAL deducts from earnings_balance');
            console.log('5. ✅ DEPOSIT APPROVAL adds to principal_balance');
            console.log('6. ✅ COMPREHENSIVE FINANCIAL REPORTS with separation');
            console.log('============================================\n');
            
            console.log('✅ ALL ORIGINAL ENDPOINTS PRESERVED AND ENHANCED');
            console.log('✅ READY FOR DEPLOYMENT');
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
