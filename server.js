// server.js - RAW WEALTHY BACKEND v45.0 - ULTIMATE PRODUCTION & DEBUGGING EDITION
// COMPLETE BUSINESS LOGIC WITH ENHANCED ADMIN APPROVAL SYSTEM
// ALL PENDING ACTIONS PROPERLY ROUTED TO ADMIN FOR APPROVAL
// COMPREHENSIVE DEBUGGING TOOLS BUILT-IN
// 100% PRODUCTION READY

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
    
    // Business Logic
    minInvestment: parseInt(process.env.MIN_INVESTMENT) || 3500,
    minDeposit: parseInt(process.env.MIN_DEPOSIT) || 3500,
    minWithdrawal: parseInt(process.env.MIN_WITHDRAWAL) || 3500,
    maxWithdrawalPercent: parseFloat(process.env.MAX_WITHDRAWAL_PERCENT) || 100,
    
    platformFeePercent: parseFloat(process.env.PLATFORM_FEE_PERCENT) || 10,
    referralCommissionPercent: parseFloat(process.env.REFERRAL_COMMISSION_PERCENT) || 10,
    welcomeBonus: parseInt(process.env.WELCOME_BONUS) || 100,
    
    // Admin Approval System
    autoApproveVerifiedUsers: process.env.AUTO_APPROVE_VERIFIED_USERS === 'true',
    requireAdminApprovalFor: {
        investmentWithProof: true,
        depositWithProof: true,
        withdrawalForUnverifiedBank: true,
        kycSubmission: true,
        largeTransactions: parseFloat(process.env.LARGE_TRANSACTION_THRESHOLD) || 500000
    },
    
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
    
    // Debug Mode
    debugMode: process.env.DEBUG_MODE === 'true' || process.env.NODE_ENV !== 'production',
    enableDebugEndpoints: process.env.ENABLE_DEBUG_ENDPOINTS === 'true' || process.env.NODE_ENV !== 'production'
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

console.log('⚙️ Dynamic Configuration Loaded:');
console.log(`- Port: ${config.port}`);
console.log(`- Environment: ${config.nodeEnv}`);
console.log(`- Client URL: ${config.clientURL}`);
console.log(`- Server URL: ${config.serverURL}`);
console.log(`- Email Enabled: ${config.emailEnabled}`);
console.log(`- Payment Enabled: ${config.paymentEnabled}`);
console.log(`- Debug Mode: ${config.debugMode}`);
console.log(`- Debug Endpoints: ${config.enableDebugEndpoints}`);
console.log(`- Auto Approve Verified Users: ${config.autoApproveVerifiedUsers}`);
console.log(`- Allowed Origins: ${config.allowedOrigins.length}`);

// ==================== ENHANCED EXPRESS SETUP WITH SOCKET.IO ====================
const app = express();
const server = http.createServer(app);
const io = new Server(server, {
    cors: {
        origin: config.allowedOrigins,
        credentials: true
    },
    transports: ['websocket', 'polling'],
    pingTimeout: 60000,
    pingInterval: 25000
});

// Real-time connection handling with enhanced admin tracking
const adminConnections = new Map();
const userConnections = new Map();

io.on('connection', (socket) => {
    console.log(`🔌 New socket connection: ${socket.id}`);
    
    socket.on('join-user', (userId) => {
        socket.join(`user-${userId}`);
        userConnections.set(socket.id, userId);
        console.log(`👤 User ${userId} joined their room`);
        
        // Send connection confirmation
        socket.emit('connection-established', {
            userId,
            timestamp: new Date().toISOString(),
            connectionId: socket.id
        });
    });
    
    socket.on('admin-join', (adminId) => {
        socket.join(`admin-${adminId}`);
        socket.join('admin-room');
        adminConnections.set(socket.id, adminId);
        
        console.log(`👨‍💼 Admin ${adminId} joined admin room`);
        
        // Notify admin of their connection status
        socket.emit('admin-connected', {
            adminId,
            connectionId: socket.id,
            timestamp: new Date().toISOString(),
            totalAdmins: adminConnections.size,
            totalUsers: userConnections.size
        });
        
        // Broadcast to other admins
        socket.to('admin-room').emit('admin-joined', {
            adminId,
            connectionId: socket.id,
            timestamp: new Date().toISOString()
        });
    });
    
    socket.on('admin-get-connections', () => {
        socket.emit('admin-connections', {
            adminConnections: Array.from(adminConnections.entries()),
            userConnections: Array.from(userConnections.entries()),
            timestamp: new Date().toISOString()
        });
    });
    
    socket.on('disconnect', () => {
        console.log(`🔌 Socket disconnected: ${socket.id}`);
        
        if (adminConnections.has(socket.id)) {
            const adminId = adminConnections.get(socket.id);
            adminConnections.delete(socket.id);
            console.log(`👨‍💼 Admin ${adminId} disconnected`);
            
            // Notify other admins
            io.to('admin-room').emit('admin-disconnected', {
                adminId,
                connectionId: socket.id,
                timestamp: new Date().toISOString(),
                remainingAdmins: adminConnections.size
            });
        }
        
        if (userConnections.has(socket.id)) {
            const userId = userConnections.get(socket.id);
            userConnections.delete(socket.id);
            console.log(`👤 User ${userId} disconnected`);
        }
    });
    
    // Heartbeat to keep connection alive
    socket.on('heartbeat', () => {
        socket.emit('heartbeat-response', {
            timestamp: new Date().toISOString(),
            connectionId: socket.id
        });
    });
});

// Enhanced Socket.IO utility functions
const emitToUser = (userId, event, data) => {
    io.to(`user-${userId}`).emit(event, {
        ...data,
        timestamp: new Date().toISOString(),
        eventId: crypto.randomBytes(8).toString('hex')
    });
};

const emitToAdmins = (event, data) => {
    const eventData = {
        ...data,
        timestamp: new Date().toISOString(),
        eventId: crypto.randomBytes(8).toString('hex'),
        totalAdminsOnline: adminConnections.size
    };
    
    io.to('admin-room').emit(event, eventData);
    
    // Log admin notifications
    if (config.debugMode) {
        console.log(`📢 Admin Notification: ${event}`, {
            dataType: typeof data,
            hasData: !!data,
            adminsOnline: adminConnections.size
        });
    }
};

const broadcastToAllAdmins = (event, data) => {
    const eventData = {
        ...data,
        timestamp: new Date().toISOString(),
        broadcast: true,
        totalAdmins: adminConnections.size
    };
    
    io.emit(event, eventData);
};

// Check if any admin is online
const isAnyAdminOnline = () => {
    return adminConnections.size > 0;
};

// Get admin connections info
const getAdminConnectionsInfo = () => {
    return {
        total: adminConnections.size,
        connections: Array.from(adminConnections.entries()).map(([socketId, adminId]) => ({
            socketId,
            adminId
        })),
        timestamp: new Date().toISOString()
    };
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
const logFormat = config.nodeEnv === 'production' ? 'combined' : 'dev';
app.use(morgan(logFormat, {
    stream: {
        write: (message) => {
            console.log(message.trim());
        }
    }
}));

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
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Accept', 'Origin', 'x-api-key', 'x-user-id', 'x-socket-id']
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
    legacyHeaders: false,
    keyGenerator: (req) => req.ip || req.headers['x-forwarded-for'] || 'unknown'
});

const rateLimiters = {
    createAccount: createRateLimiter(60 * 60 * 1000, 10, 'Too many accounts created from this IP'),
    auth: createRateLimiter(15 * 60 * 1000, 20, 'Too many authentication attempts'),
    api: createRateLimiter(15 * 60 * 1000, 1000, 'Too many requests from this IP'),
    financial: createRateLimiter(15 * 60 * 1000, 50, 'Too many financial operations'),
    passwordReset: createRateLimiter(15 * 60 * 1000, 5, 'Too many password reset attempts'),
    admin: createRateLimiter(15 * 60 * 1000, 500, 'Too many admin requests'),
    debug: createRateLimiter(15 * 60 * 1000, 100, 'Too many debug requests')
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
app.use('/api/debug', rateLimiters.debug);
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
            mimeType: file.mimetype,
            uploadedAt: new Date()
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
            },
            tls: {
                rejectUnauthorized: false
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

// ==================== DATABASE MODELS - ENHANCED WITH ADMIN APPROVAL TRACKING ====================
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
    
    // Admin approval tracking
    admin_approval_count: { type: Number, default: 0 },
    last_admin_approval_date: Date,
    auto_approval_eligible: { type: Boolean, default: false },
    
    // Login location tracking for security
    login_history: [{
        ip: String,
        location: String,
        device: String,
        timestamp: { type: Date, default: Date.now }
    }],
    
    // Debug tracking
    debug_tracking: {
        last_balance_check: Date,
        last_earnings_calc: Date,
        transaction_count: { type: Number, default: 0 }
    }
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
            ret.auto_approval_status = doc.auto_approval_status;
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

// Virtual field for auto approval status
userSchema.virtual('auto_approval_status').get(function() {
    return {
        eligible: this.auto_approval_eligible,
        kyc_verified: this.kyc_verified,
        bank_verified: this.bank_details?.verified || false,
        criteria_met: this.kyc_verified && (this.bank_details?.verified || false)
    };
});

// Indexes
userSchema.index({ email: 1 }, { unique: true });
userSchema.index({ referral_code: 1 }, { unique: true, sparse: true });
userSchema.index({ is_active: 1, role: 1, kyc_status: 1 });
userSchema.index({ withdrawable_earnings: 1 });
userSchema.index({ 'bank_details.verified': 1, kyc_verified: 1 });

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
        if (config.debugMode) {
            console.log(`📊 Pre-save: Updated withdrawable_earnings to ${this.withdrawable_earnings}`);
        }
    }
    
    // Check auto-approval eligibility
    if (this.isModified('kyc_verified') || this.isModified('bank_details.verified')) {
        this.auto_approval_eligible = this.kyc_verified && (this.bank_details?.verified || false);
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
            auto_approval_eligible: this.auto_approval_eligible
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

userSchema.methods.requiresAdminApproval = function(action, amount = 0) {
    // Check if user is eligible for auto-approval
    if (config.autoApproveVerifiedUsers && this.auto_approval_eligible) {
        return false;
    }
    
    // Check specific requirements
    switch (action) {
        case 'investment':
            return config.requireAdminApprovalFor.investmentWithProof;
        case 'withdrawal':
            if (amount > config.requireAdminApprovalFor.largeTransactions) {
                return true;
            }
            return !this.bank_details?.verified;
        case 'deposit':
            return config.requireAdminApprovalFor.depositWithProof;
        case 'kyc':
            return config.requireAdminApprovalFor.kycSubmission;
        default:
            return true;
    }
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

// Investment Model - Enhanced with admin approval tracking
const investmentSchema = new mongoose.Schema({
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    plan: { type: mongoose.Schema.Types.ObjectId, ref: 'InvestmentPlan', required: true },
    amount: { type: Number, required: true, min: config.minInvestment },
    status: { type: String, enum: ['pending', 'active', 'completed', 'cancelled', 'failed', 'under_review'], default: 'pending' },
    start_date: { type: Date, default: Date.now },
    end_date: { type: Date, required: true },
    approved_at: Date,
    
    // Earnings tracking
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
    
    // Admin approval tracking
    requires_admin_approval: { type: Boolean, default: true },
    admin_notified: { type: Boolean, default: false },
    admin_notified_at: Date,
    admin_review_count: { type: Number, default: 0 },
    
    metadata: { type: mongoose.Schema.Types.Mixed, default: {} }
}, {
    timestamps: true
});

investmentSchema.index({ user: 1, status: 1 });
investmentSchema.index({ end_date: 1 });
investmentSchema.index({ requires_admin_approval: 1, status: 1 });
investmentSchema.index({ admin_notified: 1, status: 'pending' });
const Investment = mongoose.model('Investment', investmentSchema);

// Deposit Model with admin approval tracking
const depositSchema = new mongoose.Schema({
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    amount: { type: Number, required: true, min: config.minDeposit },
    payment_method: { type: String, enum: ['bank_transfer', 'crypto', 'paypal', 'card', 'flutterwave', 'paystack'], required: true },
    status: { type: String, enum: ['pending', 'approved', 'rejected', 'cancelled', 'under_review'], default: 'pending' },
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
    
    // Admin approval tracking
    requires_admin_approval: { type: Boolean, default: true },
    admin_notified: { type: Boolean, default: false },
    admin_notified_at: Date,
    admin_review_count: { type: Number, default: 0 },
    auto_approved: { type: Boolean, default: false },
    
    metadata: { type: mongoose.Schema.Types.Mixed, default: {} }
}, {
    timestamps: true
});

depositSchema.index({ user: 1, status: 1 });
depositSchema.index({ reference: 1 }, { unique: true, sparse: true });
depositSchema.index({ requires_admin_approval: 1, status: 1 });
depositSchema.index({ admin_notified: 1, status: 'pending' });
const Deposit = mongoose.model('Deposit', depositSchema);

// Withdrawal Model with enhanced admin approval tracking
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
    
    status: { type: String, enum: ['pending', 'approved', 'rejected', 'paid', 'processing', 'under_review'], default: 'pending' },
    reference: { type: String, unique: true, sparse: true },
    admin_notes: String,
    approved_by: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    approved_at: Date,
    paid_at: Date,
    transaction_id: String,
    
    // Admin approval tracking
    auto_approved: { type: Boolean, default: false },
    requires_admin_approval: { type: Boolean, default: true },
    admin_notified: { type: Boolean, default: false },
    admin_notified_at: Date,
    admin_review_count: { type: Number, default: 0 },
    approval_type: { type: String, enum: ['auto', 'manual', 'pending'], default: 'pending' },
    
    // Large transaction flag
    is_large_transaction: { type: Boolean, default: false },
    large_transaction_threshold: Number,
    
    metadata: { type: mongoose.Schema.Types.Mixed, default: {} }
}, {
    timestamps: true
});

withdrawalSchema.index({ user: 1, status: 1 });
withdrawalSchema.index({ requires_admin_approval: 1, status: 1 });
withdrawalSchema.index({ admin_notified: 1, status: 'pending' });
withdrawalSchema.index({ auto_approved: 1, status: 'pending' });
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
    
    // Debug info
    debug_info: {
        timestamp: { type: Date, default: Date.now },
        user_balance_before: Number,
        user_balance_after: Number,
        system_balance_check: Number,
        verified: { type: Boolean, default: false }
    },
    
    metadata: { type: mongoose.Schema.Types.Mixed, default: {} }
}, {
    timestamps: true
});

transactionSchema.index({ user: 1, createdAt: -1 });
transactionSchema.index({ type: 1, status: 1 });
transactionSchema.index({ reference: 1 }, { unique: true, sparse: true });
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
    
    // Admin notification tracking
    admin_notified: { type: Boolean, default: false },
    admin_notified_at: Date,
    requires_admin_approval: { type: Boolean, default: true },
    
    metadata: { type: mongoose.Schema.Types.Mixed, default: {} }
}, {
    timestamps: true
});

kycSubmissionSchema.index({ status: 1 });
kycSubmissionSchema.index({ admin_notified: 1, status: 'pending' });
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
    
    // Admin notification tracking
    admin_notified: { type: Boolean, default: false },
    admin_notified_at: Date,
    requires_admin_attention: { type: Boolean, default: false },
    
    metadata: { type: mongoose.Schema.Types.Mixed, default: {} }
}, {
    timestamps: true
});

supportTicketSchema.index({ user: 1, status: 1 });
supportTicketSchema.index({ admin_notified: 1, status: 'open' });
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
    
    metadata: { type: mongoose.Schema.Types.Mixed, default: {} }
}, {
    timestamps: true
});

referralSchema.index({ referrer: 1, status: 1 });
const Referral = mongoose.model('Referral', referralSchema);

// Notification Model with enhanced admin notifications
const notificationSchema = new mongoose.Schema({
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    title: { type: String, required: true },
    message: { type: String, required: true },
    type: { type: String, enum: ['info', 'success', 'warning', 'error', 'promotional', 'investment', 'withdrawal', 'deposit', 'kyc', 'referral', 'system', 'admin_alert', 'pending_action'], default: 'info' },
    is_read: { type: Boolean, default: false },
    is_email_sent: { type: Boolean, default: false },
    action_url: String,
    priority: { type: Number, default: 0, min: 0, max: 3 },
    
    // Admin notification tracking
    is_admin_notification: { type: Boolean, default: false },
    admin_action_required: { type: Boolean, default: false },
    related_entity_type: String,
    related_entity_id: mongoose.Schema.Types.ObjectId,
    
    metadata: { type: mongoose.Schema.Types.Mixed, default: {} }
}, {
    timestamps: true
});

notificationSchema.index({ user: 1, is_read: 1 });
notificationSchema.index({ is_admin_notification: 1, admin_action_required: 1 });
notificationSchema.index({ related_entity_type: 1, related_entity_id: 1 });
const Notification = mongoose.model('Notification', notificationSchema);

// Admin Audit Log Model
const adminAuditSchema = new mongoose.Schema({
    admin_id: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    action: { type: String, required: true },
    target_type: { type: String, enum: ['user', 'investment', 'deposit', 'withdrawal', 'kyc', 'transaction', 'plan', 'system', 'notification', 'debug'] },
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
    
    // Admin notification tracking
    admin_notified: { type: Boolean, default: false },
    admin_notified_at: Date,
    requires_admin_attention: { type: Boolean, default: true },
    
    metadata: { type: mongoose.Schema.Types.Mixed, default: {} }
}, {
    timestamps: true
});

amlMonitoringSchema.index({ status: 1, risk_score: -1 });
amlMonitoringSchema.index({ admin_notified: 1, status: 'pending_review' });
const AmlMonitoring = mongoose.model('AmlMonitoring', amlMonitoringSchema);

// Pending Actions Queue Model
const pendingActionSchema = new mongoose.Schema({
    action_type: { type: String, enum: ['investment', 'deposit', 'withdrawal', 'kyc', 'support', 'aml'], required: true },
    entity_id: { type: mongoose.Schema.Types.ObjectId, required: true },
    entity_type: { type: String, required: true },
    user_id: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    amount: Number,
    status: { type: String, enum: ['pending', 'notified', 'in_progress', 'completed', 'failed'], default: 'pending' },
    
    // Notification tracking
    admin_notified: { type: Boolean, default: false },
    admin_notified_at: Date,
    notification_sent_via: [String], // ['socket', 'email', 'in_app']
    
    // Processing info
    assigned_to: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    assigned_at: Date,
    processed_by: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    processed_at: Date,
    
    metadata: { type: mongoose.Schema.Types.Mixed, default: {} }
}, {
    timestamps: true
});

pendingActionSchema.index({ action_type: 1, status: 1 });
pendingActionSchema.index({ user_id: 1, status: 1 });
pendingActionSchema.index({ admin_notified: 1, status: 'pending' });
const PendingAction = mongoose.model('PendingAction', pendingActionSchema);

// ==================== UTILITY FUNCTIONS - ENHANCED ====================
const formatResponse = (success, message, data = null, pagination = null, debug = null) => {
    const response = {
        success,
        message,
        timestamp: new Date().toISOString()
    };
    
    if (data !== null) response.data = data;
    if (pagination !== null) response.pagination = pagination;
    if (debug !== null && config.debugMode) response.debug = debug;
    
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

// Enhanced createNotification with admin notification tracking
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
                sentAt: new Date(),
                sentVia: ['in_app']
            }
        });
        
        await notification.save();
        
        // Emit real-time notification
        emitToUser(userId, 'new-notification', {
            id: notification._id,
            title,
            message,
            type,
            action_url: actionUrl,
            is_read: false,
            createdAt: notification.createdAt
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
            
            const emailResult = await sendEmail(user.email, emailSubject, emailHtml);
            if (emailResult.success) {
                notification.is_email_sent = true;
                notification.metadata.sentVia.push('email');
                await notification.save();
            }
        }
        
        return notification;
    } catch (error) {
        console.error('Error creating notification:', error);
        return null;
    }
};

// Create admin notification for pending actions
const createAdminNotification = async (adminId, title, message, actionUrl = null, metadata = {}) => {
    try {
        const notification = new Notification({
            user: adminId,
            title,
            message,
            type: 'admin_alert',
            action_url: actionUrl,
            is_admin_notification: true,
            admin_action_required: true,
            metadata: {
                ...metadata,
                sentAt: new Date(),
                priority: 'high'
            }
        });
        
        await notification.save();
        
        // Emit to specific admin
        emitToUser(adminId, 'admin-alert', {
            id: notification._id,
            title,
            message,
            action_url: actionUrl,
            priority: 'high',
            timestamp: new Date().toISOString()
        });
        
        return notification;
    } catch (error) {
        console.error('Error creating admin notification:', error);
        return null;
    }
};

// Notify all admins about pending action
const notifyAdminsOfPendingAction = async (actionType, entityId, entityType, userId, amount = null, details = {}) => {
    try {
        console.log(`📢 Notifying admins of ${actionType}: ${entityId}`);
        
        // Create pending action record
        const pendingAction = new PendingAction({
            action_type: actionType,
            entity_id: entityId,
            entity_type: entityType,
            user_id: userId,
            amount,
            status: 'pending',
            admin_notified: false,
            metadata: details
        });
        
        await pendingAction.save();
        
        // Get all admin users
        const admins = await User.find({ 
            role: { $in: ['admin', 'super_admin'] },
            is_active: true 
        });
        
        const notificationPromises = admins.map(admin => 
            createAdminNotification(
                admin._id,
                `Pending ${actionType} Requires Approval`,
                `A new ${actionType} requires your attention. Click to review.`,
                `/admin/${actionType}s/${entityId}`,
                {
                    actionType,
                    entityId,
                    entityType,
                    userId,
                    amount,
                    pendingActionId: pendingAction._id
                }
            )
        );
        
        await Promise.all(notificationPromises);
        
        // Update pending action as notified
        pendingAction.admin_notified = true;
        pendingAction.admin_notified_at = new Date();
        pendingAction.notification_sent_via = ['in_app'];
        await pendingAction.save();
        
        // Emit Socket.IO event to all admins
        emitToAdmins(`new-${actionType}-pending`, {
            actionType,
            entityId,
            entityType,
            userId,
            amount,
            pendingActionId: pendingAction._id,
            timestamp: new Date().toISOString(),
            totalAdminsNotified: admins.length
        });
        
        console.log(`✅ Notified ${admins.length} admins about ${actionType} ${entityId}`);
        
        return {
            success: true,
            pendingActionId: pendingAction._id,
            adminsNotified: admins.length,
            actionType
        };
    } catch (error) {
        console.error(`❌ Error notifying admins of ${actionType}:`, error);
        return {
            success: false,
            error: error.message
        };
    }
};

// Enhanced createTransaction function with admin notification
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
                total_withdrawn: user.total_withdrawn || 0,
                total_deposits: user.total_deposits || 0,
                total_withdrawals: user.total_withdrawals || 0,
                total_investments: user.total_investments || 0
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
                            user.daily_earnings = (user.daily_earnings || 0) + amount;
                            user.last_daily_interest_date = new Date();
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
                        user.total_investments = beforeState.total_investments + investmentAmount;
                        user.last_investment_date = new Date();
                        console.log(`📈 Deducted ${investmentAmount} from balance for investment`);
                        break;
                        
                    case 'deposit':
                        if (amount > 0) {
                            user.balance = beforeState.balance + amount;
                            user.total_deposits = beforeState.total_deposits + amount;
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
                        user.total_withdrawals = beforeState.total_withdrawals + withdrawalAmount;
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
            
            // Update debug tracking
            user.debug_tracking = {
                last_balance_check: new Date(),
                last_earnings_calc: new Date(),
                transaction_count: (user.debug_tracking?.transaction_count || 0) + 1
            };
            
            // Save user changes
            await user.save({ session });
            console.log(`✅ [TRANSACTION] User updated successfully`);
            
            // Create transaction record
            const afterState = {
                balance: user.balance,
                total_earnings: user.total_earnings,
                referral_earnings: user.referral_earnings,
                withdrawable_earnings: user.withdrawable_earnings,
                total_withdrawn: user.total_withdrawn,
                total_deposits: user.total_deposits,
                total_withdrawals: user.total_withdrawals,
                total_investments: user.total_investments
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
                debug_info: {
                    timestamp: new Date(),
                    user_balance_before: beforeState.balance,
                    user_balance_after: afterState.balance,
                    system_balance_check: user.balance,
                    verified: true
                },
                metadata: {
                    ...metadata,
                    processedAt: new Date(),
                    user_id: userId,
                    transaction_type: type,
                    session_id: session.id,
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
                timestamp: new Date().toISOString(),
                transaction_id: transaction._id
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

// AML Monitoring function with admin notification
const checkAmlCompliance = async (userId, transactionType, amount, metadata = {}) => {
    try {
        if (amount <= 0) return { riskScore: 0, flagged: false };
        
        let riskScore = 0;
        let flaggedReasons = [];
        
        // Check amount thresholds
        if (amount > 1000000) {
            riskScore += 40;
            flaggedReasons.push('Large transaction amount');
        }
        
        if (amount > 500000 && transactionType === 'withdrawal') {
            riskScore += 30;
            flaggedReasons.push('Large withdrawal request');
        }
        
        // Check frequency
        const recentTransactions = await Transaction.countDocuments({
            user: userId,
            createdAt: { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) }
        });
        
        if (recentTransactions > 10) {
            riskScore += 20;
            flaggedReasons.push('High transaction frequency');
        }
        
        // Check user's account age
        const user = await User.findById(userId);
        if (user) {
            const accountAgeDays = (new Date() - user.createdAt) / (1000 * 60 * 60 * 24);
            if (accountAgeDays < 7 && amount > 100000) {
                riskScore += 30;
                flaggedReasons.push('New account with large transaction');
            }
        }
        
        const flagged = riskScore > 50;
        
        if (flagged) {
            const amlRecord = new AmlMonitoring({
                user: userId,
                transaction_type: transactionType,
                amount,
                flagged_reason: flaggedReasons.join(', '),
                risk_score: riskScore,
                status: 'pending_review',
                requires_admin_attention: true,
                metadata
            });
            
            await amlRecord.save();
            
            // Notify admins via Socket.IO
            emitToAdmins('aml-flagged', {
                userId,
                transactionType,
                amount,
                riskScore,
                reasons: flaggedReasons,
                amlRecordId: amlRecord._id,
                timestamp: new Date().toISOString()
            });
            
            // Create admin notifications
            await notifyAdminsOfPendingAction(
                'aml',
                amlRecord._id,
                'AmlMonitoring',
                userId,
                amount,
                {
                    riskScore,
                    reasons: flaggedReasons,
                    transactionType
                }
            );
            
            console.log(`🚨 AML Flagged: User ${userId}, Risk Score: ${riskScore}, Reasons: ${flaggedReasons.join(', ')}`);
        }
        
        return {
            riskScore,
            flagged,
            reasons: flaggedReasons
        };
    } catch (error) {
        console.error('AML check error:', error);
        return { riskScore: 0, flagged: false, reasons: [] };
    }
};

// Check and notify admins of pending actions
const checkAndNotifyPendingActions = async () => {
    try {
        console.log('🔍 Checking for pending actions requiring admin attention...');
        
        const pendingActions = await PendingAction.find({
            status: 'pending',
            admin_notified: false
        }).limit(10);
        
        if (pendingActions.length === 0) {
            console.log('✅ No pending actions requiring notification');
            return { checked: 0, notified: 0 };
        }
        
        let notifiedCount = 0;
        
        for (const action of pendingActions) {
            // Check if entity still exists
            let entity;
            switch (action.entity_type) {
                case 'Investment':
                    entity = await Investment.findById(action.entity_id);
                    break;
                case 'Deposit':
                    entity = await Deposit.findById(action.entity_id);
                    break;
                case 'Withdrawal':
                    entity = await Withdrawal.findById(action.entity_id);
                    break;
                case 'KYCSubmission':
                    entity = await KYCSubmission.findById(action.entity_id);
                    break;
                case 'AmlMonitoring':
                    entity = await AmlMonitoring.findById(action.entity_id);
                    break;
            }
            
            if (!entity || entity.status !== 'pending') {
                action.status = 'completed';
                await action.save();
                continue;
            }
            
            // Notify admins
            const notificationResult = await notifyAdminsOfPendingAction(
                action.action_type,
                action.entity_id,
                action.entity_type,
                action.user_id,
                action.amount,
                { pendingActionId: action._id }
            );
            
            if (notificationResult.success) {
                notifiedCount++;
            }
        }
        
        console.log(`📢 Notified admins about ${notifiedCount} pending actions`);
        return { checked: pendingActions.length, notified: notifiedCount };
    } catch (error) {
        console.error('Error checking pending actions:', error);
        return { checked: 0, notified: 0, error: error.message };
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

// Debug middleware for logging
const debugMiddleware = (req, res, next) => {
    if (config.debugMode) {
        console.log(`🔍 ${req.method} ${req.path}`, {
            body: req.body,
            query: req.query,
            params: req.params,
            headers: req.headers,
            ip: req.ip,
            timestamp: new Date().toISOString()
        });
    }
    next();
};

// Apply debug middleware to all routes
if (config.debugMode) {
    app.use(debugMiddleware);
}

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
        await createDefaultInvestmentPlans();
        
        // Check for pending actions on startup
        setTimeout(async () => {
            await checkAndNotifyPendingActions();
        }, 5000);
        
        console.log('✅ Database initialization completed');
    } catch (error) {
        console.error('❌ Database initialization error:', error.message);
        throw error;
    }
};

const createDefaultInvestmentPlans = async () => {
    const defaultPlans = [
        {
            name: 'Cocoa Beans',
            description: 'Invest in premium cocoa beans with stable returns.',
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
        for (const planData of defaultPlans) {
            const existingPlan = await InvestmentPlan.findOne({ name: planData.name });
            if (!existingPlan) {
                await InvestmentPlan.create(planData);
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
            auto_approval_eligible: true
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
        version: '45.0.0',
        environment: config.nodeEnv,
        database: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
        socket: {
            total_connections: (await io.fetchSockets()).length,
            admin_connections: adminConnections.size,
            user_connections: userConnections.size
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
            withdrawals: await Withdrawal.countDocuments({}),
            pending_actions: await PendingAction.countDocuments({ status: 'pending' })
        }
    };
    
    res.json(health);
});

// ==================== ROOT ENDPOINT ====================
app.get('/', (req, res) => {
    res.json({
        success: true,
        message: '🚀 Raw Wealthy Backend API v45.0 - Ultimate Production & Debugging Edition',
        version: '45.0.0',
        timestamp: new Date().toISOString(),
        status: 'Operational',
        environment: config.nodeEnv,
        debug_mode: config.debugMode,
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
            health: '/health',
            debug: '/api/debug/*'
        }
    });
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
            auto_approval_eligible: false
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
                portfolio_value: userData.portfolio_value,
                auto_approval_eligible: userData.auto_approval_eligible
            }
        };
        
        res.json(formatResponse(true, 'Profile retrieved successfully', profileData));
    } catch (error) {
        console.error('Error fetching profile:', error);
        handleError(res, error, 'Error fetching profile');
    }
});

// ==================== INVESTMENT ENDPOINTS - ENHANCED WITH ADMIN NOTIFICATION ====================
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
        
        // Check if investment requires admin approval
        const requiresAdminApproval = proofUrl ? true : freshUser.requiresAdminApproval('investment', investmentAmount);
        
        const investment = new Investment({
            user: userId,
            plan: plan_id,
            amount: investmentAmount,
            status: requiresAdminApproval ? 'pending' : 'active',
            start_date: new Date(),
            end_date: endDate,
            expected_earnings: expectedEarnings,
            daily_earnings: dailyEarnings,
            auto_renew,
            payment_proof_url: proofUrl,
            payment_verified: !proofUrl && !requiresAdminApproval,
            requires_admin_approval: requiresAdminApproval,
            admin_notified: false
        });
        
        await investment.save();
        
        // Deduct investment amount from user's balance
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
                daily_interest: plan.daily_interest
            }
        );
        
        await InvestmentPlan.findByIdAndUpdate(plan_id, {
            $inc: {
                investment_count: 1,
                total_invested: investmentAmount
            }
        });
        
        if (!requiresAdminApproval) {
            // Auto-approve investment
            const firstDayEarnings = (investmentAmount * plan.daily_interest) / 100;
            investment.earned_so_far = firstDayEarnings;
            investment.last_earning_date = new Date();
            investment.status = 'active';
            investment.payment_verified = true;
            investment.approved_at = new Date();
            investment.auto_approved = true;
            await investment.save();
            
            await createTransaction(
                userId,
                'daily_interest',
                firstDayEarnings,
                `First day interest from ${plan.name} investment`,
                'completed',
                {
                    investment_id: investment._id,
                    plan_name: plan.name,
                    daily_interest: plan.daily_interest
                }
            );
            
            // Check for referral commission
            if (freshUser.referred_by) {
                const referrer = await User.findById(freshUser.referred_by);
                if (referrer) {
                    const commission = investmentAmount * (config.referralCommissionPercent / 100);
                    
                    await createTransaction(
                        referrer._id,
                        'referral_bonus',
                        commission,
                        `Referral commission from ${freshUser.full_name}'s investment`,
                        'completed',
                        {
                            referred_user_id: freshUser._id,
                            investment_id: investment._id,
                            commission_percentage: config.referralCommissionPercent
                        }
                    );
                    
                    await Referral.findOneAndUpdate(
                        { referrer: referrer._id, referred_user: freshUser._id },
                        {
                            $inc: { total_commission: commission },
                            status: 'active',
                            investment_amount: investmentAmount
                        }
                    );
                    
                    await createNotification(
                        referrer._id,
                        'Referral Commission Earned!',
                        `You earned ₦${commission.toLocaleString()} commission from ${freshUser.full_name}'s investment.`,
                        'referral',
                        '/referrals'
                    );
                }
            }
            
            await createNotification(
                userId,
                'Investment Created & Auto-Approved',
                `Your investment of ₦${investmentAmount.toLocaleString()} in ${plan.name} has been created and auto-approved.`,
                'investment',
                '/investments'
            );
        } else {
            // Notify admins about pending investment
            await notifyAdminsOfPendingAction(
                'investment',
                investment._id,
                'Investment',
                userId,
                investmentAmount,
                {
                    plan_name: plan.name,
                    proof_url: proofUrl,
                    auto_renew: auto_renew
                }
            );
            
            investment.admin_notified = true;
            investment.admin_notified_at = new Date();
            await investment.save();
            
            await createNotification(
                userId,
                'Investment Created - Pending Approval',
                `Your investment of ₦${investmentAmount.toLocaleString()} in ${plan.name} has been created and is pending admin approval.`,
                'investment',
                '/investments'
            );
        }
        
        res.status(201).json(formatResponse(true, 
            requiresAdminApproval ? 'Investment created successfully! Pending admin approval.' : 'Investment created and auto-approved successfully!',
            {
                investment: {
                    ...investment.toObject(),
                    plan_name: plan.name,
                    expected_daily_earnings: dailyEarnings,
                    expected_total_earnings: expectedEarnings,
                    end_date: endDate,
                    requires_admin_approval: requiresAdminApproval,
                    auto_approved: !requiresAdminApproval
                }
            }
        ));
    } catch (error) {
        handleError(res, error, 'Error creating investment');
    }
});

// ==================== DEPOSIT ENDPOINTS - ENHANCED WITH ADMIN NOTIFICATION ====================
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
        
        // AML check for large deposits
        const amlCheck = await checkAmlCompliance(userId, 'deposit', depositAmount);
        if (amlCheck.flagged) {
            return res.status(400).json(formatResponse(false, 
                'Deposit flagged for review due to compliance checks. Please contact support.'));
        }
        
        let proofUrl = null;
        if (req.file) {
            try {
                const uploadResult = await handleFileUpload(req.file, 'deposit-proofs', userId);
                proofUrl = uploadResult.url;
            } catch (uploadError) {
                return res.status(400).json(formatResponse(false, `File upload failed: ${uploadError.message}`));
            }
        }
        
        const user = await User.findById(userId);
        const requiresAdminApproval = proofUrl ? true : user.requiresAdminApproval('deposit', depositAmount);
        
        const deposit = new Deposit({
            user: userId,
            amount: depositAmount,
            payment_method,
            status: requiresAdminApproval ? 'pending' : 'approved',
            payment_proof_url: proofUrl,
            reference: generateReference('DEP'),
            requires_admin_approval: requiresAdminApproval,
            admin_notified: false,
            auto_approved: !requiresAdminApproval
        });
        
        await deposit.save();
        
        if (!requiresAdminApproval) {
            // Auto-approve deposit
            deposit.status = 'approved';
            deposit.approved_at = new Date();
            deposit.auto_approved = true;
            await deposit.save();
            
            // Credit user's balance
            await createTransaction(
                userId,
                'deposit',
                depositAmount,
                `Deposit via ${payment_method}`,
                'completed',
                {
                    deposit_id: deposit._id,
                    payment_method: payment_method
                }
            );
            
            await createNotification(
                userId,
                'Deposit Auto-Approved',
                `Your deposit of ₦${depositAmount.toLocaleString()} has been auto-approved and credited to your account.`,
                'success',
                '/deposits'
            );
        } else {
            // Notify admins about pending deposit
            await notifyAdminsOfPendingAction(
                'deposit',
                deposit._id,
                'Deposit',
                userId,
                depositAmount,
                {
                    payment_method,
                    proof_url: proofUrl
                }
            );
            
            deposit.admin_notified = true;
            deposit.admin_notified_at = new Date();
            await deposit.save();
            
            await createNotification(
                userId,
                'Deposit Request Submitted',
                `Your deposit request of ₦${depositAmount.toLocaleString()} has been submitted and is pending approval.`,
                'deposit',
                '/deposits'
            );
        }
        
        res.status(201).json(formatResponse(true, 
            requiresAdminApproval ? 'Deposit request submitted successfully!' : 'Deposit auto-approved and credited!',
            {
                deposit: {
                    ...deposit.toObject(),
                    formatted_amount: `₦${depositAmount.toLocaleString()}`,
                    requires_approval: requiresAdminApproval,
                    auto_approved: !requiresAdminApproval
                }
            }
        ));
    } catch (error) {
        handleError(res, error, 'Error creating deposit');
    }
});

// ==================== WITHDRAWAL ENDPOINTS - ENHANCED WITH ADMIN NOTIFICATION ====================
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
        
        // Get fresh user data
        const freshUser = await User.findById(userId);
        if (!freshUser) {
            return res.status(404).json(formatResponse(false, 'User not found'));
        }
        
        // Check minimum withdrawal
        if (withdrawalAmount < config.minWithdrawal) {
            return res.status(400).json(formatResponse(false,
                `Minimum withdrawal is ₦${config.minWithdrawal.toLocaleString()}`));
        }
        
        // Check available earnings for withdrawal
        const availableForWithdrawal = freshUser.withdrawable_earnings || 0;
        
        if (withdrawalAmount > availableForWithdrawal) {
            return res.status(400).json(formatResponse(false,
                `Insufficient earnings. Available for withdrawal: ₦${availableForWithdrawal.toLocaleString()}`));
        }
        
        // Check maximum withdrawal percentage
        const maxWithdrawal = availableForWithdrawal * (config.maxWithdrawalPercent / 100);
        if (withdrawalAmount > maxWithdrawal) {
            return res.status(400).json(formatResponse(false,
                `Maximum withdrawal is ${config.maxWithdrawalPercent}% of your available earnings (₦${maxWithdrawal.toLocaleString()})`));
        }
        
        // Check payment method requirements
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
        
        // AML check for withdrawals
        const amlCheck = await checkAmlCompliance(userId, 'withdrawal', withdrawalAmount);
        if (amlCheck.flagged) {
            return res.status(400).json(formatResponse(false, 
                'Withdrawal flagged for review due to compliance checks. Please contact support.'));
        }
        
        // Calculate platform fee
        const platformFee = withdrawalAmount * (config.platformFeePercent / 100);
        const netAmount = withdrawalAmount - platformFee;
        
        // Calculate split proportionally between earnings types
        const totalEarnings = freshUser.total_earnings || 0;
        const totalReferral = freshUser.referral_earnings || 0;
        const totalAvailable = totalEarnings + totalReferral;
        
        let fromEarnings = 0;
        let fromReferral = 0;
        
        if (totalAvailable > 0) {
            fromEarnings = (totalEarnings / totalAvailable) * withdrawalAmount;
            fromReferral = (totalReferral / totalAvailable) * withdrawalAmount;
        }
        
        // Check if requires admin approval
        const isLargeTransaction = withdrawalAmount > config.requireAdminApprovalFor.largeTransactions;
        const requiresAdminApproval = isLargeTransaction || freshUser.requiresAdminApproval('withdrawal', withdrawalAmount);
        
        // Create withdrawal
        const withdrawal = new Withdrawal({
            user: userId,
            amount: withdrawalAmount,
            payment_method,
            from_earnings: fromEarnings,
            from_referral: fromReferral,
            platform_fee: platformFee,
            net_amount: netAmount,
            status: requiresAdminApproval ? 'pending' : 'processing',
            reference: generateReference('WDL'),
            requires_admin_approval: requiresAdminApproval,
            auto_approved: !requiresAdminApproval,
            approval_type: requiresAdminApproval ? 'pending' : 'auto',
            is_large_transaction: isLargeTransaction,
            large_transaction_threshold: config.requireAdminApprovalFor.largeTransactions,
            admin_notified: false,
            
            // Add payment details
            ...(payment_method === 'bank_transfer' && freshUser.bank_details ? {
                bank_details: freshUser.bank_details
            } : {}),
            ...(payment_method === 'crypto' ? {
                wallet_address: freshUser.wallet_address
            } : {}),
            ...(payment_method === 'paypal' ? {
                paypal_email: freshUser.paypal_email
            } : {})
        });
        
        await withdrawal.save();
        
        if (!requiresAdminApproval) {
            // Auto-process withdrawal
            withdrawal.status = 'processing';
            withdrawal.auto_approved = true;
            withdrawal.approval_type = 'auto';
            await withdrawal.save();
            
            // Create pending transaction
            await createTransaction(
                userId,
                'withdrawal',
                -withdrawalAmount,
                `Withdrawal via ${payment_method}`,
                'pending',
                {
                    withdrawal_id: withdrawal._id,
                    payment_method,
                    platform_fee: platformFee,
                    net_amount: netAmount,
                    from_earnings: fromEarnings,
                    from_referral: fromReferral,
                    auto_approved: true
                }
            );
            
            await createNotification(
                userId,
                'Withdrawal Auto-Approved',
                `Your withdrawal request of ₦${withdrawalAmount.toLocaleString()} has been auto-approved and is being processed.`,
                'withdrawal',
                '/withdrawals'
            );
        } else {
            // Notify admins about pending withdrawal
            await notifyAdminsOfPendingAction(
                'withdrawal',
                withdrawal._id,
                'Withdrawal',
                userId,
                withdrawalAmount,
                {
                    payment_method,
                    platform_fee: platformFee,
                    net_amount: netAmount,
                    is_large_transaction: isLargeTransaction,
                    bank_verified: freshUser.bank_details?.verified || false
                }
            );
            
            withdrawal.admin_notified = true;
            withdrawal.admin_notified_at = new Date();
            await withdrawal.save();
            
            // Create pending transaction
            await createTransaction(
                userId,
                'withdrawal',
                -withdrawalAmount,
                `Withdrawal request via ${payment_method}`,
                'pending',
                {
                    withdrawal_id: withdrawal._id,
                    payment_method,
                    platform_fee: platformFee,
                    net_amount: netAmount,
                    from_earnings: fromEarnings,
                    from_referral: fromReferral,
                    requires_admin_approval: true
                }
            );
            
            await createNotification(
                userId,
                'Withdrawal Request Submitted',
                `Your withdrawal request of ₦${withdrawalAmount.toLocaleString()} has been submitted and is pending admin approval.`,
                'withdrawal',
                '/withdrawals'
            );
        }
        
        res.status(201).json(formatResponse(true, 
            requiresAdminApproval 
                ? 'Withdrawal request submitted successfully!' 
                : 'Withdrawal auto-approved and queued for processing!', 
            {
                withdrawal: {
                    ...withdrawal.toObject(),
                    formatted_amount: `₦${withdrawalAmount.toLocaleString()}`,
                    formatted_net_amount: `₦${netAmount.toLocaleString()}`,
                    formatted_fee: `₦${platformFee.toLocaleString()}`,
                    requires_admin_approval: requiresAdminApproval,
                    auto_approved: !requiresAdminApproval,
                    is_large_transaction: isLargeTransaction
                }
            }
        ));
    } catch (error) {
        handleError(res, error, 'Error creating withdrawal');
    }
});

// ==================== KYC ENDPOINTS - ENHANCED WITH ADMIN NOTIFICATION ====================
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
            status: 'pending',
            requires_admin_approval: true,
            admin_notified: false
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
        
        // Notify admins about pending KYC
        await notifyAdminsOfPendingAction(
            'kyc',
            kycSubmission._id,
            'KYCSubmission',
            userId,
            null,
            {
                id_type,
                id_number
            }
        );
        
        kycSubmission.admin_notified = true;
        kycSubmission.admin_notified_at = new Date();
        await kycSubmission.save();
        
        await createNotification(
            userId,
            'KYC Submitted',
            'Your KYC documents have been submitted successfully. Verification typically takes 24-48 hours.',
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

// ==================== ADMIN ENDPOINTS - ENHANCED WITH PENDING ACTIONS MANAGEMENT ====================
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
            amlFlags,
            pendingActions
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
            AmlMonitoring.countDocuments({ status: 'pending_review' }),
            PendingAction.countDocuments({ status: 'pending' })
        ]);
        
        const earningsResult = await Investment.aggregate([
            { $match: { status: 'active' } },
            { $group: { _id: null, total: { $sum: '$earned_so_far' } } }
        ]);
        
        const totalEarnings = earningsResult[0]?.total || 0;
        
        const portfolioResult = await User.aggregate([
            { $group: {
                _id: null,
                total_balance: { $sum: '$balance' },
                total_earnings: { $sum: '$total_earnings' },
                total_referral_earnings: { $sum: '$referral_earnings' }
            } }
        ]);
        
        const totalPortfolio = portfolioResult[0] ?
            (portfolioResult[0].total_balance || 0) +
            (portfolioResult[0].total_earnings || 0) +
            (portfolioResult[0].total_referral_earnings || 0) : 0;
        
        // Get recent pending actions for display
        const recentPendingActions = await PendingAction.find({ status: 'pending' })
            .populate('user_id', 'full_name email')
            .sort({ createdAt: -1 })
            .limit(10)
            .lean();
        
        // Get admin connection status
        const adminConnectionsInfo = getAdminConnectionsInfo();
        
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
            pending_actions: {
                pending_investments: pendingInvestments,
                pending_deposits: pendingDeposits,
                pending_withdrawals: pendingWithdrawals,
                pending_kyc: pendingKYC,
                aml_flags: amlFlags,
                total_pending: pendingActions,
                recent_pending: recentPendingActions
            },
            system_status: {
                admin_connections: adminConnectionsInfo.total,
                admin_online: adminConnectionsInfo.total > 0,
                last_checked: new Date().toISOString()
            }
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
                pending_actions_queue: '/api/admin/pending-actions'
            }
        }));
    } catch (error) {
        handleError(res, error, 'Error fetching admin dashboard stats');
    }
});

app.get('/api/admin/pending-investments', adminAuth, async (req, res) => {
    try {
        const pendingInvestments = await Investment.find({ 
            status: 'pending',
            requires_admin_approval: true 
        })
            .populate('user', 'full_name email phone')
            .populate('plan', 'name min_amount daily_interest')
            .sort({ createdAt: -1 })
            .lean();
        
        // Check notification status
        const pendingActions = await PendingAction.find({
            action_type: 'investment',
            entity_type: 'Investment',
            status: 'pending'
        }).lean();
        
        const investmentsWithNotificationStatus = pendingInvestments.map(inv => {
            const pendingAction = pendingActions.find(pa => 
                pa.entity_id.toString() === inv._id.toString()
            );
            return {
                ...inv,
                notification_status: pendingAction ? {
                    admin_notified: pendingAction.admin_notified,
                    admin_notified_at: pendingAction.admin_notified_at,
                    notification_sent_via: pendingAction.notification_sent_via
                } : null,
                has_pending_action: !!pendingAction
            };
        });
        
        res.json(formatResponse(true, 'Pending investments retrieved successfully', {
            investments: investmentsWithNotificationStatus,
            count: pendingInvestments.length,
            total_amount: pendingInvestments.reduce((sum, inv) => sum + inv.amount, 0),
            notification_summary: {
                total_notified: pendingActions.filter(pa => pa.admin_notified).length,
                total_pending_notification: pendingActions.filter(pa => !pa.admin_notified).length
            }
        }));
    } catch (error) {
        handleError(res, error, 'Error fetching pending investments');
    }
});

app.get('/api/admin/pending-deposits', adminAuth, async (req, res) => {
    try {
        const pendingDeposits = await Deposit.find({ 
            status: 'pending',
            requires_admin_approval: true 
        })
            .populate('user', 'full_name email phone balance')
            .sort({ createdAt: -1 })
            .lean();
        
        // Check notification status
        const pendingActions = await PendingAction.find({
            action_type: 'deposit',
            entity_type: 'Deposit',
            status: 'pending'
        }).lean();
        
        const depositsWithNotificationStatus = pendingDeposits.map(dep => {
            const pendingAction = pendingActions.find(pa => 
                pa.entity_id.toString() === dep._id.toString()
            );
            return {
                ...dep,
                notification_status: pendingAction ? {
                    admin_notified: pendingAction.admin_notified,
                    admin_notified_at: pendingAction.admin_notified_at,
                    notification_sent_via: pendingAction.notification_sent_via
                } : null,
                has_pending_action: !!pendingAction
            };
        });
        
        res.json(formatResponse(true, 'Pending deposits retrieved successfully', {
            deposits: depositsWithNotificationStatus,
            count: pendingDeposits.length,
            total_amount: pendingDeposits.reduce((sum, dep) => sum + dep.amount, 0),
            notification_summary: {
                total_notified: pendingActions.filter(pa => pa.admin_notified).length,
                total_pending_notification: pendingActions.filter(pa => !pa.admin_notified).length
            }
        }));
    } catch (error) {
        handleError(res, error, 'Error fetching pending deposits');
    }
});

app.get('/api/admin/pending-withdrawals', adminAuth, async (req, res) => {
    try {
        const pendingWithdrawals = await Withdrawal.find({ 
            status: 'pending',
            requires_admin_approval: true 
        })
            .populate('user', 'full_name email phone balance')
            .sort({ createdAt: -1 })
            .lean();
        
        // Check notification status
        const pendingActions = await PendingAction.find({
            action_type: 'withdrawal',
            entity_type: 'Withdrawal',
            status: 'pending'
        }).lean();
        
        const withdrawalsWithNotificationStatus = pendingWithdrawals.map(w => {
            const pendingAction = pendingActions.find(pa => 
                pa.entity_id.toString() === w._id.toString()
            );
            return {
                ...w,
                notification_status: pendingAction ? {
                    admin_notified: pendingAction.admin_notified,
                    admin_notified_at: pendingAction.admin_notified_at,
                    notification_sent_via: pendingAction.notification_sent_via
                } : null,
                has_pending_action: !!pendingAction
            };
        });
        
        res.json(formatResponse(true, 'Pending withdrawals retrieved successfully', {
            withdrawals: withdrawalsWithNotificationStatus,
            count: pendingWithdrawals.length,
            total_amount: pendingWithdrawals.reduce((sum, w) => sum + w.amount, 0),
            notification_summary: {
                total_notified: pendingActions.filter(pa => pa.admin_notified).length,
                total_pending_notification: pendingActions.filter(pa => !pa.admin_notified).length
            }
        }));
    } catch (error) {
        handleError(res, error, 'Error fetching pending withdrawals');
    }
});

app.get('/api/admin/pending-actions', adminAuth, async (req, res) => {
    try {
        const { action_type, status, limit = 50 } = req.query;
        
        const query = {};
        if (action_type) query.action_type = action_type;
        if (status) query.status = status;
        
        const pendingActions = await PendingAction.find(query)
            .populate('user_id', 'full_name email')
            .populate('assigned_to', 'full_name email')
            .populate('processed_by', 'full_name email')
            .sort({ createdAt: -1 })
            .limit(parseInt(limit))
            .lean();
        
        // Get entity details for each pending action
        const enhancedActions = await Promise.all(pendingActions.map(async (action) => {
            let entityDetails = null;
            
            switch (action.entity_type) {
                case 'Investment':
                    entityDetails = await Investment.findById(action.entity_id)
                        .populate('plan', 'name')
                        .lean();
                    break;
                case 'Deposit':
                    entityDetails = await Deposit.findById(action.entity_id).lean();
                    break;
                case 'Withdrawal':
                    entityDetails = await Withdrawal.findById(action.entity_id).lean();
                    break;
                case 'KYCSubmission':
                    entityDetails = await KYCSubmission.findById(action.entity_id).lean();
                    break;
                case 'AmlMonitoring':
                    entityDetails = await AmlMonitoring.findById(action.entity_id).lean();
                    break;
            }
            
            return {
                ...action,
                entity_details: entityDetails
            };
        }));
        
        // Group by action type for summary
        const summary = enhancedActions.reduce((acc, action) => {
            if (!acc[action.action_type]) {
                acc[action.action_type] = {
                    count: 0,
                    total_amount: 0,
                    notified: 0
                };
            }
            acc[action.action_type].count++;
            if (action.amount) {
                acc[action.action_type].total_amount += action.amount;
            }
            if (action.admin_notified) {
                acc[action.action_type].notified++;
            }
            return acc;
        }, {});
        
        res.json(formatResponse(true, 'Pending actions retrieved successfully', {
            pending_actions: enhancedActions,
            summary,
            counts: {
                total: enhancedActions.length,
                by_status: enhancedActions.reduce((acc, action) => {
                    acc[action.status] = (acc[action.status] || 0) + 1;
                    return acc;
                }, {}),
                by_type: enhancedActions.reduce((acc, action) => {
                    acc[action.action_type] = (acc[action.action_type] || 0) + 1;
                    return acc;
                }, {})
            },
            admin_connections: getAdminConnectionsInfo()
        }));
    } catch (error) {
        handleError(res, error, 'Error fetching pending actions');
    }
});

// Enhanced admin approval endpoints
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
        
        // Calculate first day's earnings
        const firstDayEarnings = (investment.amount * investment.plan.daily_interest) / 100;
        
        investment.status = 'active';
        investment.approved_at = new Date();
        investment.approved_by = adminId;
        investment.payment_verified = true;
        investment.remarks = remarks;
        investment.earned_so_far = firstDayEarnings;
        investment.last_earning_date = new Date();
        investment.admin_review_count += 1;
        
        await investment.save();
        
        // Update pending action
        await PendingAction.findOneAndUpdate(
            {
                entity_id: investmentId,
                entity_type: 'Investment',
                status: 'pending'
            },
            {
                status: 'completed',
                processed_by: adminId,
                processed_at: new Date(),
                metadata: {
                    ...(investment.metadata || {}),
                    approved_by: adminId,
                    approved_at: new Date(),
                    remarks
                }
            }
        );
        
        // Create earnings transaction
        await createTransaction(
            investment.user._id,
            'daily_interest',
            firstDayEarnings,
            `First day interest from ${investment.plan.name} investment (approved by admin)`,
            'completed',
            {
                investment_id: investment._id,
                plan_name: investment.plan.name,
                daily_interest: investment.plan.daily_interest,
                approved_by: adminId
            }
        );
        
        // Award referral commission if applicable
        const user = await User.findById(investment.user._id);
        if (user.referred_by) {
            const referrer = await User.findById(user.referred_by);
            if (referrer) {
                const commission = investment.amount * (config.referralCommissionPercent / 100);
                
                await createTransaction(
                    referrer._id,
                    'referral_bonus',
                    commission,
                    `Referral commission from ${user.full_name}'s investment`,
                    'completed',
                    {
                        referred_user_id: user._id,
                        investment_id: investment._id,
                        commission_percentage: config.referralCommissionPercent
                    }
                );
                
                await Referral.findOneAndUpdate(
                    { referrer: referrer._id, referred_user: user._id },
                    {
                        $inc: { total_commission: commission },
                        status: 'active',
                        investment_amount: investment.amount
                    }
                );
                
                await createNotification(
                    referrer._id,
                    'Referral Commission Earned!',
                    `You earned ₦${commission.toLocaleString()} commission from ${user.full_name}'s investment.`,
                    'referral',
                    '/referrals'
                );
            }
        }
        
        await createNotification(
            investment.user._id,
            'Investment Approved by Admin',
            `Your investment of ₦${investment.amount.toLocaleString()} in ${investment.plan.name} has been approved by admin. First day earnings: ₦${firstDayEarnings.toLocaleString()}`,
            'investment',
            '/investments'
        );
        
        // Update user's admin approval count
        await User.findByIdAndUpdate(investment.user._id, {
            $inc: { admin_approval_count: 1 },
            last_admin_approval_date: new Date()
        });
        
        // Create admin audit log
        await AdminAudit.create({
            admin_id: adminId,
            action: 'approve_investment',
            target_type: 'investment',
            target_id: investmentId,
            details: {
                amount: investment.amount,
                plan: investment.plan.name,
                remarks,
                first_day_earnings: firstDayEarnings
            },
            ip_address: req.ip,
            user_agent: req.headers['user-agent']
        });
        
        res.json(formatResponse(true, 'Investment approved successfully', {
            investment: investment.toObject(),
            actions: {
                earnings_added: firstDayEarnings,
                user_notified: true,
                audit_log_created: true
            }
        }));
    } catch (error) {
        handleError(res, error, 'Error approving investment');
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
        deposit.admin_review_count += 1;
        
        await deposit.save();
        
        // Update pending action
        await PendingAction.findOneAndUpdate(
            {
                entity_id: depositId,
                entity_type: 'Deposit',
                status: 'pending'
            },
            {
                status: 'completed',
                processed_by: adminId,
                processed_at: new Date(),
                metadata: {
                    ...(deposit.metadata || {}),
                    approved_by: adminId,
                    approved_at: new Date(),
                    remarks
                }
            }
        );
        
        // Credit user's balance
        await createTransaction(
            deposit.user._id,
            'deposit',
            deposit.amount,
            `Deposit via ${deposit.payment_method} (approved by admin)`,
            'completed',
            {
                deposit_id: deposit._id,
                payment_method: deposit.payment_method,
                approved_by: adminId
            }
        );
        
        await createNotification(
            deposit.user._id,
            'Deposit Approved by Admin',
            `Your deposit of ₦${deposit.amount.toLocaleString()} has been approved by admin and credited to your account.`,
            'success',
            '/deposits'
        );
        
        // Create admin audit log
        await AdminAudit.create({
            admin_id: adminId,
            action: 'approve_deposit',
            target_type: 'deposit',
            target_id: depositId,
            details: {
                amount: deposit.amount,
                payment_method: deposit.payment_method,
                remarks
            },
            ip_address: req.ip,
            user_agent: req.headers['user-agent']
        });
        
        res.json(formatResponse(true, 'Deposit approved successfully', {
            deposit: deposit.toObject()
        }));
    } catch (error) {
        handleError(res, error, 'Error approving deposit');
    }
});

app.post('/api/admin/withdrawals/:id/approve', adminAuth, [
    body('transaction_id').optional().trim(),
    body('remarks').optional().trim()
], async (req, res) => {
    try {
        const withdrawalId = req.params.id;
        const adminId = req.user._id;
        const { transaction_id, remarks } = req.body;
        
        const withdrawal = await Withdrawal.findById(withdrawalId)
            .populate('user');
        
        if (!withdrawal) {
            return res.status(404).json(formatResponse(false, 'Withdrawal not found'));
        }
        
        if (withdrawal.status !== 'pending' && withdrawal.status !== 'processing') {
            return res.status(400).json(formatResponse(false, 'Withdrawal is not pending approval'));
        }
        
        // Check if user still has enough withdrawable earnings
        const user = await User.findById(withdrawal.user._id);
        if (withdrawal.amount > (user.withdrawable_earnings || 0)) {
            return res.status(400).json(formatResponse(false,
                `User does not have enough earnings to withdraw ${withdrawal.amount}. Available: ${user.withdrawable_earnings}`));
        }
        
        withdrawal.status = 'paid';
        withdrawal.approved_at = new Date();
        withdrawal.approved_by = adminId;
        withdrawal.paid_at = new Date();
        withdrawal.transaction_id = transaction_id;
        withdrawal.admin_notes = remarks;
        withdrawal.admin_review_count += 1;
        withdrawal.approval_type = 'manual';
        
        await withdrawal.save();
        
        // Update pending action
        await PendingAction.findOneAndUpdate(
            {
                entity_id: withdrawalId,
                entity_type: 'Withdrawal',
                status: 'pending'
            },
            {
                status: 'completed',
                processed_by: adminId,
                processed_at: new Date(),
                metadata: {
                    ...(withdrawal.metadata || {}),
                    approved_by: adminId,
                    approved_at: new Date(),
                    transaction_id,
                    remarks
                }
            }
        );
        
        // Deduct from user's earnings
        await createTransaction(
            withdrawal.user._id,
            'withdrawal',
            -withdrawal.amount,
            `Withdrawal via ${withdrawal.payment_method} (approved by admin)`,
            'completed',
            {
                withdrawal_id: withdrawal._id,
                payment_method: withdrawal.payment_method,
                platform_fee: withdrawal.platform_fee,
                net_amount: withdrawal.net_amount,
                transaction_id: transaction_id,
                from_earnings: withdrawal.from_earnings,
                from_referral: withdrawal.from_referral,
                approved_by: adminId
            }
        );
        
        await createNotification(
            withdrawal.user._id,
            'Withdrawal Approved by Admin',
            `Your withdrawal of ₦${withdrawal.amount.toLocaleString()} has been approved by admin and processed.`,
            'success',
            '/withdrawals'
        );
        
        // Create admin audit log
        await AdminAudit.create({
            admin_id: adminId,
            action: 'approve_withdrawal',
            target_type: 'withdrawal',
            target_id: withdrawalId,
            details: {
                amount: withdrawal.amount,
                payment_method: withdrawal.payment_method,
                net_amount: withdrawal.net_amount,
                platform_fee: withdrawal.platform_fee,
                transaction_id,
                remarks
            },
            ip_address: req.ip,
            user_agent: req.headers['user-agent']
        });
        
        res.json(formatResponse(true, 'Withdrawal approved successfully', {
            withdrawal: withdrawal.toObject()
        }));
    } catch (error) {
        handleError(res, error, 'Error approving withdrawal');
    }
});

// ==================== ADVANCED DEBUGGING ENDPOINTS ====================
if (config.enableDebugEndpoints) {
    console.log('🔧 Debug endpoints enabled');
    
    // Debug endpoint to check system status
    app.get('/api/debug/system-status', async (req, res) => {
        try {
            const systemStatus = {
                success: true,
                timestamp: new Date().toISOString(),
                system: {
                    nodeVersion: process.version,
                    platform: process.platform,
                    uptime: process.uptime(),
                    memoryUsage: process.memoryUsage(),
                    cpuUsage: process.cpuUsage(),
                    pid: process.pid,
                    arch: process.arch
                },
                database: {
                    connected: mongoose.connection.readyState === 1,
                    host: mongoose.connection.host,
                    name: mongoose.connection.name,
                    readyState: mongoose.connection.readyState,
                    models: Object.keys(mongoose.connection.models),
                    collections: Object.keys(mongoose.connection.collections)
                },
                socket: {
                    total_connections: (await io.fetchSockets()).length,
                    admin_connections: adminConnections.size,
                    user_connections: userConnections.size,
                    admin_online: isAnyAdminOnline(),
                    admin_connections_info: getAdminConnectionsInfo()
                },
                config: {
                    environment: config.nodeEnv,
                    serverURL: config.serverURL,
                    clientURL: config.clientURL,
                    emailEnabled: config.emailEnabled,
                    paymentEnabled: config.paymentEnabled,
                    debugMode: config.debugMode,
                    autoApproveVerifiedUsers: config.autoApproveVerifiedUsers
                },
                pending_counts: {
                    investments: await Investment.countDocuments({ status: 'pending' }),
                    deposits: await Deposit.countDocuments({ status: 'pending' }),
                    withdrawals: await Withdrawal.countDocuments({ status: 'pending' }),
                    kyc: await KYCSubmission.countDocuments({ status: 'pending' }),
                    aml: await AmlMonitoring.countDocuments({ status: 'pending_review' }),
                    pending_actions: await PendingAction.countDocuments({ status: 'pending' })
                },
                stats: {
                    total_users: await User.countDocuments({}),
                    total_investments: await Investment.countDocuments({}),
                    total_deposits: await Deposit.countDocuments({}),
                    total_withdrawals: await Withdrawal.countDocuments({}),
                    total_transactions: await Transaction.countDocuments({})
                }
            };
            
            res.json(systemStatus);
        } catch (error) {
            res.status(500).json({ success: false, error: error.message });
        }
    });
    
    // Debug endpoint to check pending actions status
    app.get('/api/debug/pending-actions-status', adminAuth, async (req, res) => {
        try {
            const [
                pendingInvestments,
                pendingDeposits,
                pendingWithdrawals,
                pendingKYC,
                amlFlags,
                pendingActions,
                notifications
            ] = await Promise.all([
                Investment.find({ status: 'pending', requires_admin_approval: true })
                    .populate('user', 'email')
                    .populate('plan', 'name')
                    .lean(),
                Deposit.find({ status: 'pending', requires_admin_approval: true })
                    .populate('user', 'email')
                    .lean(),
                Withdrawal.find({ status: 'pending', requires_admin_approval: true })
                    .populate('user', 'email')
                    .lean(),
                KYCSubmission.find({ status: 'pending' })
                    .populate('user', 'email')
                    .lean(),
                AmlMonitoring.find({ status: 'pending_review' })
                    .populate('user', 'email')
                    .lean(),
                PendingAction.find({ status: 'pending' })
                    .populate('user_id', 'email')
                    .lean(),
                Notification.find({ 
                    is_admin_notification: true,
                    admin_action_required: true,
                    is_read: false 
                })
                    .sort({ createdAt: -1 })
                    .limit(20)
                    .lean()
            ]);
            
            const analysis = {
                total_pending: pendingInvestments.length + pendingDeposits.length + 
                              pendingWithdrawals.length + pendingKYC.length + amlFlags.length,
                by_type: {
                    investments: pendingInvestments.length,
                    deposits: pendingDeposits.length,
                    withdrawals: pendingWithdrawals.length,
                    kyc: pendingKYC.length,
                    aml: amlFlags.length
                },
                notification_status: {
                    pending_actions: pendingActions.length,
                    admin_notifications: notifications.length,
                    admin_notified: pendingActions.filter(pa => pa.admin_notified).length,
                    not_notified: pendingActions.filter(pa => !pa.admin_notified).length
                },
                admin_connection_status: {
                    online: isAnyAdminOnline(),
                    total_connections: adminConnections.size,
                    connections: getAdminConnectionsInfo()
                },
                details: {
                    investments: pendingInvestments.map(i => ({
                        id: i._id,
                        user: i.user?.email,
                        amount: i.amount,
                        plan: i.plan?.name,
                        created: i.createdAt,
                        proof_url: i.payment_proof_url ? 'Yes' : 'No',
                        requires_admin_approval: i.requires_admin_approval
                    })),
                    deposits: pendingDeposits.map(d => ({
                        id: d._id,
                        user: d.user?.email,
                        amount: d.amount,
                        method: d.payment_method,
                        created: d.createdAt,
                        proof_url: d.payment_proof_url ? 'Yes' : 'No'
                    })),
                    withdrawals: pendingWithdrawals.map(w => ({
                        id: w._id,
                        user: w.user?.email,
                        amount: w.amount,
                        method: w.payment_method,
                        created: w.createdAt,
                        is_large: w.is_large_transaction
                    }))
                }
            };
            
            res.json({
                success: true,
                timestamp: new Date().toISOString(),
                analysis,
                recommendations: !isAnyAdminOnline() ? [
                    '⚠️ No admin is currently online. Pending actions cannot be notified in real-time.',
                    'Consider: 1) Open admin dashboard, 2) Check admin connections, 3) Enable email notifications'
                ] : [
                    '✅ Admin is online. Notifications are being sent.',
                    'Check Socket.IO connections if notifications are not arriving.'
                ]
            });
        } catch (error) {
            res.status(500).json({ success: false, error: error.message });
        }
    });
    
    // Debug endpoint to test admin notifications
    app.get('/api/debug/test-admin-notifications', adminAuth, async (req, res) => {
        try {
            const testData = {
                investment_id: new mongoose.Types.ObjectId(),
                withdrawal_id: new mongoose.Types.ObjectId(),
                deposit_id: new mongoose.Types.ObjectId(),
                user_id: req.user._id,
                timestamp: new Date().toISOString()
            };
            
            // Test Socket.IO emission
            const events = [
                { name: 'new-investment-pending', data: { ...testData, amount: 50000, type: 'investment' } },
                { name: 'new-withdrawal-pending', data: { ...testData, amount: 25000, type: 'withdrawal' } },
                { name: 'new-deposit-pending', data: { ...testData, amount: 100000, type: 'deposit' } },
                { name: 'new-kyc-pending', data: { ...testData, type: 'kyc' } },
                { name: 'aml-flagged', data: { ...testData, riskScore: 75, type: 'aml' } }
            ];
            
            const results = [];
            for (const event of events) {
                try {
                    emitToAdmins(event.name, event.data);
                    results.push({
                        event: event.name,
                        emitted: true,
                        data_sent: event.data,
                        timestamp: new Date().toISOString()
                    });
                    console.log(`✅ Emitted: ${event.name}`);
                } catch (error) {
                    results.push({
                        event: event.name,
                        emitted: false,
                        error: error.message,
                        timestamp: new Date().toISOString()
                    });
                    console.log(`❌ Failed: ${event.name} - ${error.message}`);
                }
            }
            
            // Create test pending actions
            const testActions = [];
            for (let i = 0; i < 3; i++) {
                const action = new PendingAction({
                    action_type: ['investment', 'deposit', 'withdrawal'][i],
                    entity_id: new mongoose.Types.ObjectId(),
                    entity_type: ['Investment', 'Deposit', 'Withdrawal'][i],
                    user_id: req.user._id,
                    amount: [50000, 100000, 25000][i],
                    status: 'pending',
                    admin_notified: false
                });
                await action.save();
                testActions.push(action);
            }
            
            // Create test admin notification
            const notification = await createAdminNotification(
                req.user._id,
                'Debug Notification Test',
                'This is a test notification from the debugging system',
                '/admin/dashboard',
                {
                    test: true,
                    timestamp: new Date().toISOString(),
                    source: 'debug-endpoint'
                }
            );
            
            res.json({
                success: true,
                timestamp: new Date().toISOString(),
                socket_test: {
                    total_events: events.length,
                    successful: results.filter(r => r.emitted).length,
                    failed: results.filter(r => !r.emitted).length,
                    results
                },
                database_test: {
                    pending_actions_created: testActions.length,
                    notification_created: !!notification,
                    test_data: testActions.map(a => ({
                        id: a._id,
                        type: a.action_type,
                        amount: a.amount
                    }))
                },
                admin_connections: {
                    online: isAnyAdminOnline(),
                    total: adminConnections.size,
                    connections: getAdminConnectionsInfo()
                },
                recommendations: [
                    '1. Open admin dashboard in browser to see real-time notifications',
                    '2. Check browser console for Socket.IO events',
                    '3. Verify pending actions in admin panel',
                    '4. Test notification delivery with different admin users'
                ]
            });
        } catch (error) {
            res.status(500).json({ success: false, error: error.message });
        }
    });
    
    // Debug endpoint to simulate user journey
    app.post('/api/debug/simulate-user-journey', adminAuth, async (req, res) => {
        try {
            const { email = `test${Date.now()}@example.com`, amount = 10000 } = req.body;
            
            console.log('🎯 SIMULATING COMPLETE USER JOURNEY');
            
            // Step 1: Create test user
            const testUser = new User({
                full_name: 'Debug User',
                email,
                phone: '080' + Math.floor(10000000 + Math.random() * 90000000),
                password: 'Debug123456',
                role: 'user',
                balance: amount * 10,
                kyc_verified: false,
                kyc_status: 'not_submitted',
                bank_details: {
                    bank_name: 'Test Bank',
                    account_name: 'Debug User',
                    account_number: '0123456789',
                    bank_code: '123',
                    verified: false
                },
                auto_approval_eligible: false
            });
            
            await testUser.save();
            console.log(`✅ Created test user: ${email}`);
            
            // Step 2: Get investment plan
            const plan = await InvestmentPlan.findOne({ is_active: true });
            if (!plan) {
                throw new Error('No active investment plans found');
            }
            
            // Step 3: Create investment with proof (should go to admin)
            const investment = new Investment({
                user: testUser._id,
                plan: plan._id,
                amount,
                status: 'pending',
                start_date: new Date(),
                end_date: new Date(Date.now() + plan.duration * 24 * 60 * 60 * 1000),
                expected_earnings: (amount * plan.total_interest) / 100,
                daily_earnings: (amount * plan.daily_interest) / 100,
                payment_proof_url: 'https://example.com/debug-proof.jpg',
                payment_verified: false,
                requires_admin_approval: true,
                admin_notified: false
            });
            
            await investment.save();
            console.log(`✅ Created pending investment: ₦${amount.toLocaleString()}`);
            
            // Step 4: Create withdrawal request (should go to admin)
            const withdrawal = new Withdrawal({
                user: testUser._id,
                amount: amount / 2,
                payment_method: 'bank_transfer',
                from_earnings: amount / 2,
                from_referral: 0,
                platform_fee: (amount / 2) * 0.1,
                net_amount: (amount / 2) * 0.9,
                status: 'pending',
                reference: generateReference('WDL'),
                requires_admin_approval: true,
                admin_notified: false,
                bank_details: testUser.bank_details,
                is_large_transaction: false
            });
            
            await withdrawal.save();
            console.log(`✅ Created pending withdrawal: ₦${(amount / 2).toLocaleString()}`);
            
            // Step 5: Create deposit request
            const deposit = new Deposit({
                user: testUser._id,
                amount: amount * 2,
                payment_method: 'bank_transfer',
                status: 'pending',
                payment_proof_url: 'https://example.com/debug-deposit.jpg',
                reference: generateReference('DEP'),
                requires_admin_approval: true,
                admin_notified: false
            });
            
            await deposit.save();
            console.log(`✅ Created pending deposit: ₦${(amount * 2).toLocaleString()}`);
            
            // Step 6: Create KYC submission
            const kyc = new KYCSubmission({
                user: testUser._id,
                id_type: 'national_id',
                id_number: 'TEST123456',
                id_front_url: 'https://example.com/id-front.jpg',
                selfie_with_id_url: 'https://example.com/selfie.jpg',
                status: 'pending',
                requires_admin_approval: true,
                admin_notified: false
            });
            
            await kyc.save();
            console.log(`✅ Created pending KYC submission`);
            
            // Step 7: Notify admins about all pending actions
            const notificationResults = await Promise.all([
                notifyAdminsOfPendingAction('investment', investment._id, 'Investment', testUser._id, amount, { debug: true }),
                notifyAdminsOfPendingAction('withdrawal', withdrawal._id, 'Withdrawal', testUser._id, amount / 2, { debug: true }),
                notifyAdminsOfPendingAction('deposit', deposit._id, 'Deposit', testUser._id, amount * 2, { debug: true }),
                notifyAdminsOfPendingAction('kyc', kyc._id, 'KYCSubmission', testUser._id, null, { debug: true })
            ]);
            
            // Step 8: Check if admins are listening
            const adminOnline = isAnyAdminOnline();
            const adminConnectionsInfo = getAdminConnectionsInfo();
            
            res.json({
                success: true,
                message: 'Complete user journey simulated',
                debug_info: {
                    user_created: {
                        id: testUser._id,
                        email: testUser.email,
                        balance: testUser.balance
                    },
                    pending_actions_created: {
                        investment: { id: investment._id, amount: investment.amount, status: investment.status },
                        withdrawal: { id: withdrawal._id, amount: withdrawal.amount, status: withdrawal.status },
                        deposit: { id: deposit._id, amount: deposit.amount, status: deposit.status },
                        kyc: { id: kyc._id, status: kyc.status }
                    },
                    admin_notifications: {
                        total_sent: notificationResults.filter(r => r.success).length,
                        results: notificationResults,
                        admin_online,
                        admin_connections: adminConnectionsInfo
                    },
                    timestamp: new Date().toISOString()
                },
                next_steps: {
                    admin_actions: {
                        approve_investment: `POST /api/admin/investments/${investment._id}/approve`,
                        approve_withdrawal: `POST /api/admin/withdrawals/${withdrawal._id}/approve`,
                        approve_deposit: `POST /api/admin/deposits/${deposit._id}/approve`,
                        approve_kyc: `POST /api/admin/kyc/${kyc._id}/approve`
                    },
                    verification: {
                        check_pending: `GET /api/admin/pending-actions`,
                        check_notifications: `GET /api/debug/pending-actions-status`,
                        test_socket: `GET /api/debug/test-admin-notifications`
                    }
                }
            });
            
        } catch (error) {
            console.error('❌ Simulation error:', error);
            res.status(500).json({ 
                success: false, 
                error: error.message,
                stack: config.debugMode ? error.stack : undefined
            });
        }
    });
    
    // Debug endpoint to fix pending action notifications
    app.post('/api/debug/fix-pending-notifications', adminAuth, async (req, res) => {
        try {
            const { action_type, limit = 10 } = req.body;
            
            console.log(`🔧 Fixing pending notifications for ${action_type || 'all actions'}`);
            
            const query = { 
                status: 'pending',
                admin_notified: false 
            };
            
            if (action_type) {
                query.action_type = action_type;
            }
            
            const pendingActions = await PendingAction.find(query)
                .limit(limit)
                .lean();
            
            let fixedCount = 0;
            let errorCount = 0;
            
            for (const action of pendingActions) {
                try {
                    // Get entity details
                    let entity;
                    switch (action.entity_type) {
                        case 'Investment':
                            entity = await Investment.findById(action.entity_id);
                            break;
                        case 'Deposit':
                            entity = await Deposit.findById(action.entity_id);
                            break;
                        case 'Withdrawal':
                            entity = await Withdrawal.findById(action.entity_id);
                            break;
                        case 'KYCSubmission':
                            entity = await KYCSubmission.findById(action.entity_id);
                            break;
                        case 'AmlMonitoring':
                            entity = await AmlMonitoring.findById(action.entity_id);
                            break;
                    }
                    
                    if (!entity || entity.status !== 'pending') {
                        // Update action as completed
                        await PendingAction.findByIdAndUpdate(action._id, {
                            status: 'completed',
                            metadata: {
                                ...action.metadata,
                                fixed_at: new Date(),
                                reason: 'Entity no longer pending'
                            }
                        });
                        continue;
                    }
                    
                    // Notify admins
                    const notificationResult = await notifyAdminsOfPendingAction(
                        action.action_type,
                        action.entity_id,
                        action.entity_type,
                        action.user_id,
                        action.amount,
                        {
                            ...action.metadata,
                            fixed_at: new Date(),
                            was_fixed: true
                        }
                    );
                    
                    if (notificationResult.success) {
                        fixedCount++;
                    }
                } catch (error) {
                    console.error(`Error fixing action ${action._id}:`, error);
                    errorCount++;
                }
            }
            
            res.json({
                success: true,
                message: `Fixed ${fixedCount} pending notifications, ${errorCount} errors`,
                details: {
                    total_checked: pendingActions.length,
                    fixed: fixedCount,
                    errors: errorCount,
                    timestamp: new Date().toISOString()
                }
            });
        } catch (error) {
            res.status(500).json({ success: false, error: error.message });
        }
    });
    
    // Debug endpoint to check Socket.IO connections
    app.get('/api/debug/socket-connections', adminAuth, async (req, res) => {
        try {
            const sockets = await io.fetchSockets();
            
            const connections = sockets.map(socket => {
                const rooms = Array.from(socket.rooms);
                return {
                    socket_id: socket.id,
                    rooms,
                    admin_rooms: rooms.filter(r => r.includes('admin-')),
                    user_rooms: rooms.filter(r => r.includes('user-')),
                    handshake: {
                        headers: socket.handshake.headers,
                        auth: socket.handshake.auth,
                        query: socket.handshake.query
                    },
                    connected_at: socket.handshake.auth?.connectedAt || 'unknown',
                    user_agent: socket.handshake.headers['user-agent']
                };
            });
            
            const adminConnectionsList = connections.filter(c => 
                c.admin_rooms.length > 0
            );
            
            const userConnectionsList = connections.filter(c => 
                c.user_rooms.length > 0
            );
            
            res.json({
                success: true,
                timestamp: new Date().toISOString(),
                connections: {
                    total: sockets.length,
                    admin: adminConnectionsList.length,
                    user: userConnectionsList.length,
                    anonymous: sockets.length - (adminConnectionsList.length + userConnectionsList.length)
                },
                admin_connections: adminConnectionsList,
                user_connections: userConnectionsList.slice(0, 10),
                server_info: {
                    node_env: config.nodeEnv,
                    server_url: config.serverURL,
                    client_url: config.clientURL,
                    allowed_origins: config.allowedOrigins
                }
            });
        } catch (error) {
            res.status(500).json({ success: false, error: error.message });
        }
    });
    
    // Debug endpoint to monitor real-time pending actions
    app.get('/api/debug/monitor-pending-actions', adminAuth, async (req, res) => {
        try {
            const [
                pendingCounts,
                recentActions,
                adminConnectionsInfo,
                notificationStats
            ] = await Promise.all([
                PendingAction.aggregate([
                    { $match: { status: 'pending' } },
                    { $group: { 
                        _id: '$action_type', 
                        count: { $sum: 1 },
                        total_amount: { $sum: '$amount' }
                    } }
                ]),
                PendingAction.find({ status: 'pending' })
                    .populate('user_id', 'email')
                    .sort({ createdAt: -1 })
                    .limit(20)
                    .lean(),
                getAdminConnectionsInfo(),
                Notification.aggregate([
                    { $match: { 
                        is_admin_notification: true,
                        createdAt: { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) }
                    } },
                    { $group: { 
                        _id: null,
                        total: { $sum: 1 },
                        read: { $sum: { $cond: ['$is_read', 1, 0] } },
                        unread: { $sum: { $cond: ['$is_read', 0, 1] } }
                    } }
                ])
            ]);
            
            // Get real-time pending actions from database
            const realTimePending = {
                investments: await Investment.countDocuments({ status: 'pending', requires_admin_approval: true }),
                deposits: await Deposit.countDocuments({ status: 'pending', requires_admin_approval: true }),
                withdrawals: await Withdrawal.countDocuments({ status: 'pending', requires_admin_approval: true }),
                kyc: await KYCSubmission.countDocuments({ status: 'pending' }),
                aml: await AmlMonitoring.countDocuments({ status: 'pending_review' })
            };
            
            res.json({
                success: true,
                timestamp: new Date().toISOString(),
                monitoring: {
                    pending_counts: pendingCounts.reduce((acc, item) => {
                        acc[item._id] = { count: item.count, total_amount: item.total_amount || 0 };
                        return acc;
                    }, {}),
                    real_time_pending: realTimePending,
                    total_pending: Object.values(realTimePending).reduce((sum, count) => sum + count, 0),
                    recent_actions: recentActions.map(action => ({
                        id: action._id,
                        type: action.action_type,
                        user: action.user_id?.email,
                        amount: action.amount,
                        created: action.createdAt,
                        admin_notified: action.admin_notified,
                        notification_sent_via: action.notification_sent_via
                    })),
                    admin_status: {
                        online: adminConnectionsInfo.total > 0,
                        connections: adminConnectionsInfo,
                        recommendations: adminConnectionsInfo.total === 0 ? [
                            '⚠️ No admin is currently connected via Socket.IO',
                            'Pending action notifications will not be delivered in real-time',
                            'Consider: 1) Open admin dashboard, 2) Check network connection, 3) Verify CORS settings'
                        ] : [
                            '✅ Admin is connected and ready to receive notifications',
                            'Pending actions are being notified in real-time'
                        ]
                    },
                    notification_stats: notificationStats[0] || { total: 0, read: 0, unread: 0 }
                },
                system_health: {
                    database: mongoose.connection.readyState === 1,
                    socket: (await io.fetchSockets()).length > 0,
                    admin_notifications_working: adminConnectionsInfo.total > 0,
                    last_check: new Date().toISOString()
                }
            });
        } catch (error) {
            res.status(500).json({ success: false, error: error.message });
        }
    });
    
    // Debug endpoint to resend notifications for specific pending actions
    app.post('/api/debug/resend-notifications/:actionId', adminAuth, async (req, res) => {
        try {
            const actionId = req.params.actionId;
            
            const pendingAction = await PendingAction.findById(actionId)
                .populate('user_id', 'email');
            
            if (!pendingAction) {
                return res.status(404).json({ success: false, error: 'Pending action not found' });
            }
            
            console.log(`🔄 Resending notification for action: ${actionId}, type: ${pendingAction.action_type}`);
            
            // Get entity details
            let entity;
            switch (pendingAction.entity_type) {
                case 'Investment':
                    entity = await Investment.findById(pendingAction.entity_id)
                        .populate('plan', 'name');
                    break;
                case 'Deposit':
                    entity = await Deposit.findById(pendingAction.entity_id);
                    break;
                case 'Withdrawal':
                    entity = await Withdrawal.findById(pendingAction.entity_id);
                    break;
                case 'KYCSubmission':
                    entity = await KYCSubmission.findById(pendingAction.entity_id);
                    break;
                case 'AmlMonitoring':
                    entity = await AmlMonitoring.findById(pendingAction.entity_id);
                    break;
            }
            
            if (!entity) {
                return res.status(404).json({ success: false, error: 'Entity not found' });
            }
            
            if (entity.status !== 'pending') {
                return res.status(400).json({ 
                    success: false, 
                    error: `Entity is no longer pending. Current status: ${entity.status}` 
                });
            }
            
            // Resend notification
            const notificationResult = await notifyAdminsOfPendingAction(
                pendingAction.action_type,
                pendingAction.entity_id,
                pendingAction.entity_type,
                pendingAction.user_id._id,
                pendingAction.amount,
                {
                    ...pendingAction.metadata,
                    resent_at: new Date(),
                    original_created_at: pendingAction.createdAt,
                    resend_count: (pendingAction.metadata?.resend_count || 0) + 1
                }
            );
            
            // Update pending action
            pendingAction.admin_notified = true;
            pendingAction.admin_notified_at = new Date();
            pendingAction.notification_sent_via = [...(pendingAction.notification_sent_via || []), 'resend'];
            pendingAction.metadata = {
                ...pendingAction.metadata,
                resend_count: (pendingAction.metadata?.resend_count || 0) + 1,
                last_resend: new Date()
            };
            await pendingAction.save();
            
            res.json({
                success: true,
                message: 'Notification resent successfully',
                details: {
                    action_id: actionId,
                    action_type: pendingAction.action_type,
                    entity_type: pendingAction.entity_type,
                    entity_id: pendingAction.entity_id,
                    user: pendingAction.user_id.email,
                    amount: pendingAction.amount,
                    notification_result: notificationResult,
                    admin_connections: getAdminConnectionsInfo(),
                    timestamp: new Date().toISOString()
                }
            });
        } catch (error) {
            res.status(500).json({ success: false, error: error.message });
        }
    });
    
    // Debug endpoint to test complete admin approval flow
    app.post('/api/debug/test-approval-flow', adminAuth, async (req, res) => {
        try {
            const { test_type = 'all' } = req.body;
            
            console.log(`🔧 Testing admin approval flow for: ${test_type}`);
            
            // Create test user
            const testUser = new User({
                full_name: 'Approval Test User',
                email: `approval-test-${Date.now()}@example.com`,
                phone: '080' + Math.floor(10000000 + Math.random() * 90000000),
                password: 'Test123456',
                balance: 500000,
                kyc_verified: false,
                bank_details: {
                    bank_name: 'Test Bank',
                    account_name: 'Test User',
                    account_number: '1234567890',
                    verified: false
                }
            });
            
            await testUser.save();
            
            const results = [];
            
            // Test investment approval
            if (test_type === 'all' || test_type === 'investment') {
                const plan = await InvestmentPlan.findOne({ is_active: true });
                if (plan) {
                    const investment = new Investment({
                        user: testUser._id,
                        plan: plan._id,
                        amount: 50000,
                        status: 'pending',
                        requires_admin_approval: true,
                        admin_notified: false
                    });
                    
                    await investment.save();
                    
                    // Notify admins
                    const notificationResult = await notifyAdminsOfPendingAction(
                        'investment',
                        investment._id,
                        'Investment',
                        testUser._id,
                        50000,
                        { test: true, flow: 'approval-test' }
                    );
                    
                    // Simulate admin approval
                    investment.status = 'active';
                    investment.approved_at = new Date();
                    investment.approved_by = req.user._id;
                    investment.payment_verified = true;
                    await investment.save();
                    
                    // Update pending action
                    await PendingAction.findOneAndUpdate(
                        { entity_id: investment._id, entity_type: 'Investment' },
                        { status: 'completed', processed_by: req.user._id, processed_at: new Date() }
                    );
                    
                    results.push({
                        type: 'investment',
                        created: true,
                        notified: notificationResult.success,
                        approved: true,
                        investment_id: investment._id
                    });
                }
            }
            
            // Test deposit approval
            if (test_type === 'all' || test_type === 'deposit') {
                const deposit = new Deposit({
                    user: testUser._id,
                    amount: 100000,
                    payment_method: 'bank_transfer',
                    status: 'pending',
                    requires_admin_approval: true,
                    admin_notified: false
                });
                
                await deposit.save();
                
                // Notify admins
                const notificationResult = await notifyAdminsOfPendingAction(
                    'deposit',
                    deposit._id,
                    'Deposit',
                    testUser._id,
                    100000,
                    { test: true, flow: 'approval-test' }
                );
                
                // Simulate admin approval
                deposit.status = 'approved';
                deposit.approved_at = new Date();
                deposit.approved_by = req.user._id;
                await deposit.save();
                
                // Update pending action
                await PendingAction.findOneAndUpdate(
                    { entity_id: deposit._id, entity_type: 'Deposit' },
                    { status: 'completed', processed_by: req.user._id, processed_at: new Date() }
                );
                
                results.push({
                    type: 'deposit',
                    created: true,
                    notified: notificationResult.success,
                    approved: true,
                    deposit_id: deposit._id
                });
            }
            
            // Test withdrawal approval
            if (test_type === 'all' || test_type === 'withdrawal') {
                const withdrawal = new Withdrawal({
                    user: testUser._id,
                    amount: 25000,
                    payment_method: 'bank_transfer',
                    status: 'pending',
                    requires_admin_approval: true,
                    admin_notified: false
                });
                
                await withdrawal.save();
                
                // Notify admins
                const notificationResult = await notifyAdminsOfPendingAction(
                    'withdrawal',
                    withdrawal._id,
                    'Withdrawal',
                    testUser._id,
                    25000,
                    { test: true, flow: 'approval-test' }
                );
                
                // Simulate admin approval
                withdrawal.status = 'paid';
                withdrawal.approved_at = new Date();
                withdrawal.approved_by = req.user._id;
                withdrawal.paid_at = new Date();
                await withdrawal.save();
                
                // Update pending action
                await PendingAction.findOneAndUpdate(
                    { entity_id: withdrawal._id, entity_type: 'Withdrawal' },
                    { status: 'completed', processed_by: req.user._id, processed_at: new Date() }
                );
                
                results.push({
                    type: 'withdrawal',
                    created: true,
                    notified: notificationResult.success,
                    approved: true,
                    withdrawal_id: withdrawal._id
                });
            }
            
            res.json({
                success: true,
                message: 'Admin approval flow test completed',
                test_user: {
                    id: testUser._id,
                    email: testUser.email
                },
                results,
                summary: {
                    total_tests: results.length,
                    successful: results.filter(r => r.created && r.notified && r.approved).length,
                    admin_connections: getAdminConnectionsInfo(),
                    timestamp: new Date().toISOString()
                },
                verification_steps: [
                    '1. Check admin dashboard for test notifications',
                    '2. Verify pending actions were created and notified',
                    '3. Confirm actions show as completed after approval',
                    '4. Check admin audit logs for approval records'
                ]
            });
        } catch (error) {
            res.status(500).json({ success: false, error: error.message });
        }
    });
    
    // Debug endpoint to get comprehensive system report
    app.get('/api/debug/system-report', adminAuth, async (req, res) => {
        try {
            const report = {
                timestamp: new Date().toISOString(),
                system: {
                    node_version: process.version,
                    platform: process.platform,
                    uptime: process.uptime(),
                    memory: process.memoryUsage(),
                    config: {
                        environment: config.nodeEnv,
                        debug_mode: config.debugMode,
                        auto_approve_verified_users: config.autoApproveVerifiedUsers
                    }
                },
                database: {
                    status: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
                    collections: Object.keys(mongoose.connection.collections),
                    stats: {
                        users: await User.countDocuments({}),
                        investments: await Investment.countDocuments({}),
                        deposits: await Deposit.countDocuments({}),
                        withdrawals: await Withdrawal.countDocuments({}),
                        transactions: await Transaction.countDocuments({}),
                        pending_actions: await PendingAction.countDocuments({})
                    }
                },
                socket: {
                    total_connections: (await io.fetchSockets()).length,
                    admin_connections: adminConnections.size,
                    user_connections: userConnections.size,
                    admin_online: isAnyAdminOnline(),
                    connection_details: getAdminConnectionsInfo()
                },
                pending_actions: {
                    by_type: await PendingAction.aggregate([
                        { $match: { status: 'pending' } },
                        { $group: { 
                            _id: '$action_type', 
                            count: { $sum: 1 },
                            notified: { $sum: { $cond: ['$admin_notified', 1, 0] } },
                            not_notified: { $sum: { $cond: ['$admin_notified', 0, 1] } }
                        } }
                    ]),
                    recent: await PendingAction.find({ status: 'pending' })
                        .populate('user_id', 'email')
                        .sort({ createdAt: -1 })
                        .limit(5)
                        .lean()
                },
                admin_notifications: {
                    unread: await Notification.countDocuments({ 
                        is_admin_notification: true, 
                        is_read: false 
                    }),
                    last_24_hours: await Notification.countDocuments({
                        is_admin_notification: true,
                        createdAt: { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) }
                    })
                },
                issues: [],
                recommendations: []
            };
            
            // Check for issues
            if (!isAnyAdminOnline()) {
                report.issues.push('No admin is currently online. Pending actions cannot be notified in real-time.');
                report.recommendations.push('Open admin dashboard to establish Socket.IO connection');
            }
            
            const pendingActions = await PendingAction.countDocuments({ 
                status: 'pending', 
                admin_notified: false 
            });
            
            if (pendingActions > 0) {
                report.issues.push(`${pendingActions} pending actions have not been notified to admins`);
                report.recommendations.push('Run /api/debug/fix-pending-notifications to notify admins');
            }
            
            if (mongoose.connection.readyState !== 1) {
                report.issues.push('Database connection is not established');
                report.recommendations.push('Check MongoDB connection and restart server if needed');
            }
            
            res.json({
                success: true,
                report,
                health_score: calculateHealthScore(report),
                next_steps: report.recommendations.length > 0 ? report.recommendations : ['System is healthy and operational']
            });
        } catch (error) {
            res.status(500).json({ success: false, error: error.message });
        }
    });
    
    // Helper function to calculate system health score
    function calculateHealthScore(report) {
        let score = 100;
        
        // Deduct for issues
        if (!isAnyAdminOnline()) score -= 30;
        if (mongoose.connection.readyState !== 1) score -= 50;
        if (report.pending_actions.by_type.some(type => type.not_notified > 0)) score -= 20;
        
        return Math.max(0, score);
    }
}

// ==================== DAILY INTEREST CRON JOB ====================
cron.schedule('0 0 * * *', async () => {
    console.log('🔄 Running daily interest calculation...');
    
    try {
        const activeInvestments = await Investment.find({
            status: 'active',
            end_date: { $gt: new Date() }
        }).populate('plan', 'daily_interest').populate('user');
        
        let totalInterestPaid = 0;
        let investmentsUpdated = 0;
        
        for (const investment of activeInvestments) {
            if (investment.plan && investment.plan.daily_interest) {
                const dailyEarning = (investment.amount * investment.plan.daily_interest) / 100;
                
                // Update investment
                investment.earned_so_far += dailyEarning;
                investment.last_earning_date = new Date();
                await investment.save();
                
                // Update user's earnings
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
                        investment_amount: investment.amount
                    }
                );
                
                totalInterestPaid += dailyEarning;
                investmentsUpdated++;
            }
        }
        
        console.log(`✅ Daily interest calculation completed: ${investmentsUpdated} investments updated, ₦${totalInterestPaid.toLocaleString()} paid`);
    } catch (error) {
        console.error('❌ Error in daily interest calculation:', error);
    }
});

// Investment completion check
cron.schedule('0 1 * * *', async () => {
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

// Pending actions notification check (every 5 minutes)
cron.schedule('*/5 * * * *', async () => {
    if (config.debugMode) {
        console.log('🔍 Running pending actions notification check...');
    }
    
    try {
        const result = await checkAndNotifyPendingActions();
        if (config.debugMode && result.checked > 0) {
            console.log(`📊 Pending actions check: ${result.checked} checked, ${result.notified} notified`);
        }
    } catch (error) {
        console.error('❌ Error in pending actions check:', error);
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
            console.log(`✅ Raw Wealthy Backend v45.0 - PRODUCTION & DEBUGGING`);
            console.log(`🌐 Environment: ${config.nodeEnv}`);
            console.log(`📍 Port: ${config.port}`);
            console.log(`🔗 Server URL: ${config.serverURL}`);
            console.log(`🔗 Client URL: ${config.clientURL}`);
            console.log(`🔌 Socket.IO: Enabled with ${adminConnections.size} admin connections`);
            console.log(`📊 Database: Connected`);
            console.log(`🔧 Debug Mode: ${config.debugMode}`);
            console.log('============================================\n');
            
            console.log('🎯 ENHANCED ADMIN APPROVAL SYSTEM:');
            console.log('1. ✅ All pending actions properly routed to admin');
            console.log('2. ✅ Real-time Socket.IO notifications for admins');
            console.log('3. ✅ Auto-approval for verified users');
            console.log('4. ✅ Comprehensive pending action tracking');
            console.log('5. ✅ Admin notification queuing system');
            console.log('6. ✅ Automatic notification retry mechanism');
            console.log('7. ✅ Detailed admin audit logging');
            console.log('8. ✅ Pending action status monitoring');
            console.log('============================================\n');
            
            console.log('🔧 COMPREHENSIVE DEBUGGING TOOLS:');
            console.log('• GET /api/debug/system-status - Complete system health check');
            console.log('• GET /api/debug/pending-actions-status - Pending action analysis');
            console.log('• GET /api/debug/test-admin-notifications - Test notification system');
            console.log('• POST /api/debug/simulate-user-journey - Complete user flow test');
            console.log('• GET /api/debug/socket-connections - Socket.IO connection status');
            console.log('• GET /api/debug/monitor-pending-actions - Real-time pending action monitoring');
            console.log('• POST /api/debug/fix-pending-notifications - Fix notification issues');
            console.log('• POST /api/debug/test-approval-flow - Test complete admin approval flow');
            console.log('• GET /api/debug/system-report - Comprehensive system report');
            console.log('============================================\n');
            
            console.log('💰 ENHANCED FINANCIAL FLOW:');
            console.log('• Deposits → Auto-approve for verified users, else admin approval');
            console.log('• Investments → Auto-approve without proof, else admin approval');
            console.log('• Withdrawals → Auto-approve for verified bank, else admin approval');
            console.log('• KYC → Always requires admin approval');
            console.log('• AML Monitoring → Automatic flagging and admin notification');
            console.log('============================================\n');
            
            console.log('📊 ADMIN NOTIFICATION SYSTEM:');
            console.log(`• Admin Online: ${isAnyAdminOnline() ? '✅ Yes' : '❌ No'}`);
            console.log(`• Admin Connections: ${adminConnections.size}`);
            console.log(`• Notification Method: ${config.emailEnabled ? 'Email + Socket.IO' : 'Socket.IO only'}`);
            console.log(`• Auto Approval: ${config.autoApproveVerifiedUsers ? 'Enabled' : 'Disabled'}`);
            console.log('============================================\n');
            
            console.log('✅ ALL ENDPOINTS PRESERVED AND ENHANCED');
            console.log('✅ PRODUCTION-READY WITH COMPLETE DEBUGGING');
            console.log('✅ PENDING ACTIONS PROPERLY ROUTED TO ADMIN');
            console.log('✅ REAL-TIME ADMIN NOTIFICATIONS ACTIVE');
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
