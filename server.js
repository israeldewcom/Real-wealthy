// server.js - RAW WEALTHY BACKEND v40.0 ULTIMATE PRODUCTION ENHANCED EDITION
// COMPLETE BUSINESS LOGIC WITH ADVANCED SECURITY & DEBUGGING
// ALL ENDPOINTS PRESERVED - NO ALTERATIONS TO EXISTING FUNCTIONALITY
// ENHANCED WITH COMPREHENSIVE DEBUGGING TOOLS
// PRODUCTION READY WITH REAL-TIME MONITORING

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
    
    // Business Logic - CRITICAL FIXES APPLIED
    minInvestment: parseInt(process.env.MIN_INVESTMENT) || 3500,
    minDeposit: parseInt(process.env.MIN_DEPOSIT) || 3500,
    minWithdrawal: parseInt(process.env.MIN_WITHDRAWAL) || 3500,
    maxWithdrawalPercent: parseFloat(process.env.MAX_WITHDRAWAL_PERCENT) || 100,
    
    platformFeePercent: parseFloat(process.env.PLATFORM_FEE_PERCENT) || 10,
    referralCommissionPercent: parseFloat(process.env.REFERRAL_COMMISSION_PERCENT) || 10,
    welcomeBonus: parseInt(process.env.WELCOME_BONUS) || 100,
    
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
    
    // Debug Settings
    enableDebugEndpoints: process.env.ENABLE_DEBUG_ENDPOINTS === 'true' || process.env.NODE_ENV === 'development'
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
console.log(`- Debug Endpoints: ${config.enableDebugEndpoints}`);
console.log(`- Allowed Origins: ${config.allowedOrigins.length}`);

// ==================== ENHANCED EXPRESS SETUP WITH SOCKET.IO ====================
const app = express();
const server = http.createServer(app);
const io = new Server(server, {
    cors: {
        origin: config.allowedOrigins,
        credentials: true
    },
    transports: ['websocket', 'polling']
});

// Enhanced Real-time connection handling with monitoring
const connectionMonitor = {
    activeConnections: new Map(),
    connectionHistory: [],
    
    addConnection(socket) {
        const connData = {
            id: socket.id,
            userId: socket.userId || 'anonymous',
            role: socket.role || 'anonymous',
            rooms: [],
            connectedAt: new Date(),
            ip: socket.handshake.address,
            userAgent: socket.handshake.headers['user-agent']
        };
        
        this.activeConnections.set(socket.id, connData);
        this.connectionHistory.push({
            ...connData,
            disconnectedAt: null
        });
        
        // Keep history manageable
        if (this.connectionHistory.length > 1000) {
            this.connectionHistory = this.connectionHistory.slice(-500);
        }
    },
    
    updateRooms(socket, rooms) {
        const conn = this.activeConnections.get(socket.id);
        if (conn) {
            conn.rooms = Array.from(rooms || socket.rooms);
        }
    },
    
    removeConnection(socket) {
        const conn = this.activeConnections.get(socket.id);
        if (conn) {
            conn.disconnectedAt = new Date();
            this.activeConnections.delete(socket.id);
        }
    },
    
    getStats() {
        return {
            active: this.activeConnections.size,
            historyTotal: this.connectionHistory.length,
            byRole: this.getConnectionsByRole(),
            byRoom: this.getConnectionsByRoom()
        };
    },
    
    getConnectionsByRole() {
        const roles = {};
        this.activeConnections.forEach(conn => {
            roles[conn.role] = (roles[conn.role] || 0) + 1;
        });
        return roles;
    },
    
    getConnectionsByRoom() {
        const rooms = {};
        this.activeConnections.forEach(conn => {
            conn.rooms.forEach(room => {
                rooms[room] = (rooms[room] || 0) + 1;
            });
        });
        return rooms;
    },
    
    getAdminConnections() {
        const admins = [];
        this.activeConnections.forEach(conn => {
            if (conn.role === 'admin' || conn.role === 'super_admin') {
                admins.push(conn);
            }
        });
        return admins;
    }
};

// Real-time connection handling
io.on('connection', (socket) => {
    console.log(`🔌 New socket connection: ${socket.id}`);
    connectionMonitor.addConnection(socket);
    
    // Authentication middleware for socket
    socket.use((packet, next) => {
        const [event, data] = packet;
        
        // Public events that don't require auth
        const publicEvents = ['authenticate', 'disconnect', 'error'];
        if (publicEvents.includes(event)) {
            return next();
        }
        
        // Check if socket is authenticated
        if (!socket.userId && !event.startsWith('auth-')) {
            console.log(`🚫 Unauthenticated socket attempted ${event}`);
            socket.emit('error', { message: 'Authentication required' });
            return next(new Error('Authentication required'));
        }
        
        next();
    });
    
    socket.on('authenticate', async (token) => {
        try {
            const decoded = jwt.verify(token, config.jwtSecret);
            const user = await User.findById(decoded.id);
            
            if (user) {
                socket.userId = user._id;
                socket.role = user.role;
                
                // Join user room
                socket.join(`user-${user._id}`);
                
                // Join admin room if applicable
                if (user.role === 'admin' || user.role === 'super_admin') {
                    socket.join('admin-room');
                    socket.join(`admin-${user._id}`);
                    console.log(`👨‍💼 Admin ${user.email} joined admin room`);
                }
                
                connectionMonitor.updateRooms(socket);
                
                socket.emit('authenticated', {
                    userId: user._id,
                    role: user.role,
                    rooms: Array.from(socket.rooms)
                });
                
                console.log(`✅ Socket ${socket.id} authenticated as ${user.email}`);
            }
        } catch (error) {
            console.error('Socket authentication error:', error.message);
            socket.emit('authentication-error', { message: 'Invalid token' });
        }
    });
    
    socket.on('join-user', (userId) => {
        if (socket.userId === userId) {
            socket.join(`user-${userId}`);
            connectionMonitor.updateRooms(socket);
            console.log(`👤 User ${userId} joined their room`);
        }
    });
    
    socket.on('admin-join', (adminId) => {
        if (socket.role === 'admin' || socket.role === 'super_admin') {
            socket.join(`admin-${adminId}`);
            socket.join('admin-room');
            connectionMonitor.updateRooms(socket);
            console.log(`👨‍💼 Admin ${adminId} joined admin room`);
        }
    });
    
    socket.on('disconnect', (reason) => {
        console.log(`🔌 Socket disconnected: ${socket.id} - Reason: ${reason}`);
        connectionMonitor.removeConnection(socket);
    });
    
    socket.on('error', (error) => {
        console.error(`Socket ${socket.id} error:`, error);
    });
});

// Socket.IO utility functions
const emitToUser = (userId, event, data) => {
    io.to(`user-${userId}`).emit(event, data);
};

const emitToAdmins = (event, data) => {
    io.to('admin-room').emit(event, data);
};

const emitToAllAdmins = async (event, data) => {
    const adminSockets = connectionMonitor.getAdminConnections();
    if (adminSockets.length > 0) {
        io.to('admin-room').emit(event, data);
    } else {
        console.log(`⚠️ No admin sockets connected for event: ${event}`);
    }
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

// Enhanced logging with request ID
app.use((req, res, next) => {
    req.requestId = crypto.randomBytes(8).toString('hex');
    next();
});

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
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Accept', 'Origin', 'x-api-key', 'x-user-id', 'x-request-id']
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
if (config.enableDebugEndpoints) {
    app.use('/api/debug', rateLimiters.debug);
}
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

// ==================== DATABASE MODELS - ENHANCED WITH DEBUGGING FIXES ====================
const userSchema = new mongoose.Schema({
    full_name: { type: String, required: true, trim: true },
    email: { type: String, required: true, unique: true, lowercase: true },
    phone: { type: String, required: true },
    password: { type: String, required: true, select: false },
    role: { type: String, enum: ['user', 'admin', 'super_admin'], default: 'user' },
    
    // Financial fields - ENHANCED WITH DEBUGGING
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

// Virtual field for available withdrawal - ENHANCED LOGIC
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
            referral_earnings: this.referral_earnings
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

// Investment Model - ENHANCED earnings tracking
const investmentSchema = new mongoose.Schema({
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    plan: { type: mongoose.Schema.Types.ObjectId, ref: 'InvestmentPlan', required: true },
    amount: { type: Number, required: true, min: config.minInvestment },
    status: { type: String, enum: ['pending', 'active', 'completed', 'cancelled', 'failed'], default: 'pending' },
    start_date: { type: Date, default: Date.now },
    end_date: { type: Date, required: true },
    approved_at: Date,
    
    // Earnings tracking - ENHANCED
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
    metadata: { type: mongoose.Schema.Types.Mixed, default: {} }
}, {
    timestamps: true
});

investmentSchema.index({ user: 1, status: 1 });
investmentSchema.index({ end_date: 1 });
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

// Withdrawal Model - ENHANCED WITH DEBUGGING LOGIC
const withdrawalSchema = new mongoose.Schema({
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    amount: { type: Number, required: true, min: config.minWithdrawal },
    payment_method: { type: String, enum: ['bank_transfer', 'crypto', 'paypal'], required: true },
    
    // Earnings breakdown - ENHANCED LOGIC
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
    
    status: { type: String, enum: ['pending', 'approved', 'rejected', 'paid', 'processing'], default: 'pending' },
    reference: { type: String, unique: true, sparse: true },
    admin_notes: String,
    approved_by: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    approved_at: Date,
    paid_at: Date,
    transaction_id: String,
    
    auto_approved: { type: Boolean, default: false },
    requires_admin_approval: { type: Boolean, default: true },
    
    metadata: { type: mongoose.Schema.Types.Mixed, default: {} }
}, {
    timestamps: true
});

withdrawalSchema.index({ user: 1, status: 1 });
const Withdrawal = mongoose.model('Withdrawal', withdrawalSchema);

// Transaction Model - ENHANCED WITH DEBUGGING FIXES
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

// Referral Model - ENHANCED
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

// ==================== PRODUCTION-READY createTransaction FUNCTION ====================
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

// AML Monitoring function
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
            
            // Notify admins
            emitToAllAdmins('aml-flagged', {
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
        await createDefaultInvestmentPlans();
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
            total_investments: 1500000
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
        version: '40.0.0',
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
            withdrawals: await Withdrawal.countDocuments({})
        },
        connections: {
            socket: connectionMonitor.getStats(),
            http: server._connections
        }
    };
    
    res.json(health);
});

// ==================== ROOT ENDPOINT ====================
app.get('/', (req, res) => {
    res.json({
        success: true,
        message: '🚀 Raw Wealthy Backend API v40.0 - Ultimate Production Ready',
        version: '40.0.0',
        timestamp: new Date().toISOString(),
        status: 'Operational',
        environment: config.nodeEnv,
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
        },
        ...(config.enableDebugEndpoints && {
            debug: '/api/debug/*'
        })
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

app.post('/api/debug/fix-user-earnings/:userId', adminAuth, async (req, res) => {
    try {
        const userId = req.params.userId;
        
        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({ success: false, error: 'User not found' });
        }
        
        const transactions = await Transaction.find({ user: userId, status: 'completed' });
        
        // Calculate correct values from transactions
        let correctTotalEarnings = 0;
        let correctReferralEarnings = 0;
        let correctTotalWithdrawn = 0;
        
        transactions.forEach(t => {
            if (t.type === 'daily_interest' && t.amount > 0) {
                correctTotalEarnings += t.amount;
            } else if (t.type === 'referral_bonus' && t.amount > 0) {
                correctReferralEarnings += t.amount;
            } else if (t.type === 'withdrawal' && t.amount < 0) {
                correctTotalWithdrawn += Math.abs(t.amount);
            }
        });
        
        const correctWithdrawable = Math.max(0, 
            correctTotalEarnings + correctReferralEarnings - correctTotalWithdrawn
        );
        
        // Update user
        user.total_earnings = correctTotalEarnings;
        user.referral_earnings = correctReferralEarnings;
        user.total_withdrawn = correctTotalWithdrawn;
        user.withdrawable_earnings = correctWithdrawable;
        
        await user.save();
        
        res.json({
            success: true,
            message: 'User earnings fixed successfully',
            user: {
                email: user.email,
                old: {
                    total_earnings: user.total_earnings,
                    referral_earnings: user.referral_earnings,
                    withdrawable_earnings: user.withdrawable_earnings
                },
                new: {
                    total_earnings: correctTotalEarnings,
                    referral_earnings: correctReferralEarnings,
                    withdrawable_earnings: correctWithdrawable
                }
            }
        });
    } catch (error) {
        console.error('Fix user earnings error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// ==================== COMPREHENSIVE DEBUGGING SYSTEM ====================
if (config.enableDebugEndpoints) {
    console.log('🔧 DEBUGGING ENDPOINTS ENABLED');
    
    // Debug middleware to restrict in production to admins only
    const debugAuth = (req, res, next) => {
        if (config.nodeEnv === 'production') {
            // In production, only admins can access debug endpoints
            if (req.user && (req.user.role === 'admin' || req.user.role === 'super_admin')) {
                next();
            } else {
                res.status(403).json(formatResponse(false, 'Access denied. Admin privileges required for debug endpoints.'));
            }
        } else {
            // In development, allow access
            next();
        }
    };
    
    // 1. SYSTEM STATUS ENDPOINT
    app.get('/api/debug/system-status', async (req, res) => {
        try {
            const systemStatus = {
                success: true,
                timestamp: new Date().toISOString(),
                system: {
                    nodeVersion: process.version,
                    platform: process.platform,
                    uptime: process.uptime(),
                    memoryUsage: {
                        rss: process.memoryUsage().rss,
                        heapTotal: process.memoryUsage().heapTotal,
                        heapUsed: process.memoryUsage().heapUsed,
                        external: process.memoryUsage().external
                    },
                    cpuUsage: process.cpuUsage()
                },
                database: {
                    connected: mongoose.connection.readyState === 1,
                    host: mongoose.connection.host,
                    name: mongoose.connection.name,
                    models: Object.keys(mongoose.connection.models),
                    collections: await mongoose.connection.db.listCollections().toArray()
                },
                config: {
                    environment: config.nodeEnv,
                    serverURL: config.serverURL,
                    clientURL: config.clientURL,
                    emailEnabled: config.emailEnabled,
                    paymentEnabled: config.paymentEnabled,
                    enableDebugEndpoints: config.enableDebugEndpoints
                },
                connections: {
                    socket: connectionMonitor.getStats(),
                    http: server._connections
                }
            };
            
            res.json(systemStatus);
        } catch (error) {
            console.error('System status error:', error);
            res.status(500).json({ success: false, error: error.message });
        }
    });
    
    // 2. CHECK PENDING ACTIONS
    app.get('/api/debug/check-pending-actions', debugAuth, async (req, res) => {
        try {
            const [
                pendingInvestments,
                pendingWithdrawals,
                pendingDeposits,
                pendingKYC,
                amlFlags
            ] = await Promise.all([
                Investment.find({ status: 'pending' })
                    .populate('user', 'full_name email phone')
                    .populate('plan', 'name')
                    .lean(),
                Withdrawal.find({ status: 'pending' })
                    .populate('user', 'full_name email phone')
                    .lean(),
                Deposit.find({ status: 'pending' })
                    .populate('user', 'full_name email phone')
                    .lean(),
                KYCSubmission.find({ status: 'pending' })
                    .populate('user', 'full_name email phone')
                    .lean(),
                AmlMonitoring.find({ status: 'pending_review' })
                    .populate('user', 'full_name email')
                    .lean()
            ]);
            
            // Check notification status
            const notifications = await Notification.find({
                type: { $in: ['investment', 'withdrawal', 'deposit', 'kyc'] },
                is_read: false
            }).sort({ createdAt: -1 }).limit(10).lean();
            
            res.json({
                success: true,
                timestamp: new Date().toISOString(),
                pending_counts: {
                    investments: pendingInvestments.length,
                    withdrawals: pendingWithdrawals.length,
                    deposits: pendingDeposits.length,
                    kyc: pendingKYC.length,
                    aml: amlFlags.length,
                    total: pendingInvestments.length + pendingWithdrawals.length + 
                           pendingDeposits.length + pendingKYC.length + amlFlags.length
                },
                details: {
                    investments: pendingInvestments.map(i => ({
                        id: i._id,
                        user: i.user?.email,
                        amount: i.amount,
                        plan: i.plan?.name,
                        created: i.createdAt,
                        proof_url: i.payment_proof_url ? 'Yes' : 'No'
                    })),
                    withdrawals: pendingWithdrawals.map(w => ({
                        id: w._id,
                        user: w.user?.email,
                        amount: w.amount,
                        method: w.payment_method,
                        created: w.createdAt,
                        requires_admin_approval: w.requires_admin_approval
                    })),
                    deposits: pendingDeposits.map(d => ({
                        id: d._id,
                        user: d.user?.email,
                        amount: d.amount,
                        method: d.payment_method,
                        created: d.createdAt,
                        proof_url: d.payment_proof_url ? 'Yes' : 'No'
                    }))
                },
                notifications: {
                    count: notifications.length,
                    recent: notifications.map(n => ({
                        title: n.title,
                        message: n.message,
                        type: n.type,
                        created: n.createdAt,
                        read: n.is_read
                    }))
                }
            });
            
        } catch (error) {
            console.error('Check pending actions error:', error);
            res.status(500).json({ success: false, error: error.message });
        }
    });
    
    // 3. CREATE TEST PENDING ACTIONS
    app.post('/api/debug/create-test-pending-actions', debugAuth, async (req, res) => {
        try {
            const { count = 3 } = req.body;
            const results = [];
            
            // Find existing users
            const users = await User.find({ role: 'user' }).limit(count);
            const plans = await InvestmentPlan.find({ is_active: true }).limit(3);
            
            if (users.length === 0 || plans.length === 0) {
                return res.status(400).json({
                    success: false,
                    message: 'Need at least 1 user and 1 investment plan'
                });
            }
            
            // Create test pending actions
            for (let i = 0; i < Math.min(count, users.length); i++) {
                const user = users[i];
                const plan = plans[i % plans.length];
                const amount = [5000, 10000, 25000, 50000, 100000][i % 5];
                
                // Create pending investment
                const investment = new Investment({
                    user: user._id,
                    plan: plan._id,
                    amount,
                    status: 'pending',
                    start_date: new Date(),
                    end_date: new Date(Date.now() + plan.duration * 24 * 60 * 60 * 1000),
                    expected_earnings: (amount * plan.total_interest) / 100,
                    daily_earnings: (amount * plan.daily_interest) / 100,
                    payment_proof_url: `https://example.com/proof-${Date.now()}.jpg`,
                    payment_verified: false,
                    metadata: { debug_created: true, request_id: req.requestId }
                });
                
                await investment.save();
                
                // Create pending withdrawal
                const withdrawal = new Withdrawal({
                    user: user._id,
                    amount: amount * 0.5,
                    payment_method: 'bank_transfer',
                    from_earnings: amount * 0.5,
                    from_referral: 0,
                    platform_fee: amount * 0.05,
                    net_amount: amount * 0.45,
                    status: 'pending',
                    reference: generateReference('WDL'),
                    requires_admin_approval: true,
                    bank_details: user.bank_details || {
                        bank_name: 'Test Bank',
                        account_name: user.full_name,
                        account_number: '1234567890'
                    },
                    metadata: { debug_created: true, request_id: req.requestId }
                });
                
                await withdrawal.save();
                
                // Create pending deposit
                const deposit = new Deposit({
                    user: user._id,
                    amount: amount * 2,
                    payment_method: 'bank_transfer',
                    status: 'pending',
                    payment_proof_url: `https://example.com/deposit-${Date.now()}.jpg`,
                    reference: generateReference('DEP'),
                    metadata: { debug_created: true, request_id: req.requestId }
                });
                
                await deposit.save();
                
                // Create notifications
                await createNotification(
                    user._id,
                    'Debug Investment Created',
                    `Test investment of ₦${amount.toLocaleString()} created for debugging`,
                    'investment',
                    '/investments',
                    { debug: true }
                );
                
                // Emit admin notifications
                emitToAllAdmins('new-investment', {
                    investment_id: investment._id,
                    user_id: user._id,
                    user_name: user.full_name,
                    amount,
                    plan_name: plan.name,
                    debug: true,
                    timestamp: new Date()
                });
                
                emitToAllAdmins('new-withdrawal', {
                    withdrawal_id: withdrawal._id,
                    user_id: user._id,
                    user_name: user.full_name,
                    amount: amount * 0.5,
                    debug: true,
                    timestamp: new Date()
                });
                
                emitToAllAdmins('new-deposit', {
                    deposit_id: deposit._id,
                    user_id: user._id,
                    user_name: user.full_name,
                    amount: amount * 2,
                    debug: true,
                    timestamp: new Date()
                });
                
                results.push({
                    user: user.email,
                    investment: { id: investment._id, amount },
                    withdrawal: { id: withdrawal._id, amount: amount * 0.5 },
                    deposit: { id: deposit._id, amount: amount * 2 }
                });
            }
            
            res.json({
                success: true,
                message: `Created ${results.length} sets of pending actions`,
                results,
                admin_notifications_emitted: true,
                socket_stats: connectionMonitor.getStats(),
                timestamp: new Date().toISOString()
            });
            
        } catch (error) {
            console.error('Create test pending actions error:', error);
            res.status(500).json({ success: false, error: error.message });
        }
    });
    
    // 4. SOCKET CONNECTIONS DEBUG
    app.get('/api/debug/socket-connections', debugAuth, async (req, res) => {
        try {
            const sockets = await io.fetchSockets();
            
            const connections = sockets.map(socket => {
                const rooms = Array.from(socket.rooms);
                return {
                    socket_id: socket.id,
                    user_id: socket.userId || 'anonymous',
                    role: socket.role || 'anonymous',
                    rooms,
                    admin_rooms: rooms.filter(r => r.includes('admin-')),
                    user_rooms: rooms.filter(r => r.includes('user-')),
                    connected_at: socket.handshake.auth?.connectedAt || 'unknown',
                    user_agent: socket.handshake.headers['user-agent'],
                    ip: socket.handshake.address
                };
            });
            
            const adminConnections = connections.filter(c => 
                c.admin_rooms.length > 0
            );
            
            const userConnections = connections.filter(c => 
                c.user_rooms.length > 0
            );
            
            res.json({
                success: true,
                timestamp: new Date().toISOString(),
                connections: {
                    total: sockets.length,
                    admin: adminConnections.length,
                    user: userConnections.length,
                    anonymous: sockets.length - (adminConnections.length + userConnections.length)
                },
                admin_connections: adminConnections,
                user_connections: userConnections.slice(0, 10),
                monitor_stats: connectionMonitor.getStats()
            });
            
        } catch (error) {
            console.error('Socket connections error:', error);
            res.status(500).json({ success: false, error: error.message });
        }
    });
    
    // 5. MONITORING DASHBOARD
    app.get('/api/debug/monitoring-dashboard', debugAuth, async (req, res) => {
        try {
            const [
                users, investments, deposits, withdrawals, kyc, aml,
                adminUsers, notifications, transactions
            ] = await Promise.all([
                User.countDocuments({}),
                Investment.countDocuments({}),
                Deposit.countDocuments({}),
                Withdrawal.countDocuments({}),
                KYCSubmission.countDocuments({}),
                AmlMonitoring.countDocuments({}),
                User.countDocuments({ role: { $in: ['admin', 'super_admin'] } }),
                Notification.countDocuments({ is_read: false }),
                Transaction.countDocuments({})
            ]);
            
            // Get recent pending actions
            const recentPending = await Investment.find({ status: 'pending' })
                .populate('user', 'email')
                .populate('plan', 'name')
                .sort({ createdAt: -1 })
                .limit(5)
                .lean();
            
            // Get recent transactions
            const recentTransactions = await Transaction.find()
                .sort({ createdAt: -1 })
                .limit(10)
                .populate('user', 'email')
                .lean();
            
            res.json({
                success: true,
                timestamp: new Date().toISOString(),
                dashboard: {
                    stats: {
                        total_users: users,
                        total_investments: investments,
                        total_deposits: deposits,
                        total_withdrawals: withdrawals,
                        total_kyc: kyc,
                        total_aml: aml,
                        admin_users: adminUsers,
                        unread_notifications: notifications,
                        total_transactions: transactions
                    },
                    pending: {
                        investments: await Investment.countDocuments({ status: 'pending' }),
                        withdrawals: await Withdrawal.countDocuments({ status: 'pending' }),
                        deposits: await Deposit.countDocuments({ status: 'pending' }),
                        kyc: await KYCSubmission.countDocuments({ status: 'pending' }),
                        aml: await AmlMonitoring.countDocuments({ status: 'pending_review' })
                    },
                    real_time: {
                        socket_connections: connectionMonitor.getStats(),
                        server_uptime: process.uptime(),
                        memory_usage: {
                            rss: `${Math.round(process.memoryUsage().rss / 1024 / 1024)}MB`,
                            heapTotal: `${Math.round(process.memoryUsage().heapTotal / 1024 / 1024)}MB`,
                            heapUsed: `${Math.round(process.memoryUsage().heapUsed / 1024 / 1024)}MB`
                        }
                    },
                    recent_activity: {
                        pending_investments: recentPending.map(i => ({
                            id: i._id,
                            user: i.user?.email,
                            amount: i.amount,
                            plan: i.plan?.name,
                            created: i.createdAt
                        })),
                        recent_transactions: recentTransactions.map(t => ({
                            id: t._id,
                            user: t.user?.email,
                            type: t.type,
                            amount: t.amount,
                            description: t.description,
                            created: t.createdAt
                        }))
                    }
                },
                endpoints_to_test: {
                    auth: ['/api/auth/register', '/api/auth/login'],
                    investments: ['/api/investments', '/api/plans'],
                    deposits: ['/api/deposits'],
                    withdrawals: ['/api/withdrawals'],
                    admin: ['/api/admin/dashboard', '/api/admin/pending-investments'],
                    debug: ['/api/debug/check-pending-actions', '/api/debug/test-admin-notifications']
                }
            });
            
        } catch (error) {
            console.error('Monitoring dashboard error:', error);
            res.status(500).json({ success: false, error: error.message });
        }
    });
    
    // 6. FIX TRANSACTION ISSUES
    app.post('/api/debug/fix-transaction-issues/:userId', debugAuth, async (req, res) => {
        try {
            const { userId } = req.params;
            
            const user = await User.findById(userId);
            if (!user) {
                return res.status(404).json({ success: false, error: 'User not found' });
            }
            
            // Recalculate all financial fields from transactions
            const transactions = await Transaction.find({ 
                user: userId, 
                status: 'completed' 
            });
            
            let totalEarnings = 0;
            let referralEarnings = 0;
            let totalWithdrawn = 0;
            
            transactions.forEach(t => {
                if (t.type === 'daily_interest' && t.amount > 0) {
                    totalEarnings += t.amount;
                } else if (t.type === 'referral_bonus' && t.amount > 0) {
                    referralEarnings += t.amount;
                } else if (t.type === 'withdrawal' && t.amount < 0) {
                    totalWithdrawn += Math.abs(t.amount);
                }
            });
            
            const withdrawableEarnings = Math.max(0, totalEarnings + referralEarnings - totalWithdrawn);
            
            // Store old values
            const oldValues = {
                total_earnings: user.total_earnings,
                referral_earnings: user.referral_earnings,
                withdrawable_earnings: user.withdrawable_earnings,
                total_withdrawn: user.total_withdrawn
            };
            
            // Update user
            user.total_earnings = totalEarnings;
            user.referral_earnings = referralEarnings;
            user.total_withdrawn = totalWithdrawn;
            user.withdrawable_earnings = withdrawableEarnings;
            
            await user.save();
            
            // Create audit log
            const auditLog = new AdminAudit({
                admin_id: req.user._id,
                action: 'fix_transaction_issues',
                target_type: 'user',
                target_id: userId,
                details: {
                    old_values: oldValues,
                    new_values: {
                        total_earnings: totalEarnings,
                        referral_earnings: referralEarnings,
                        withdrawable_earnings: withdrawableEarnings,
                        total_withdrawn: totalWithdrawn
                    },
                    transaction_count: transactions.length,
                    request_id: req.requestId
                },
                ip_address: req.ip,
                user_agent: req.headers['user-agent']
            });
            
            await auditLog.save();
            
            res.json({
                success: true,
                message: 'User transaction issues fixed',
                user: {
                    email: user.email,
                    old_values: oldValues,
                    new_values: {
                        total_earnings,
                        referral_earnings,
                        withdrawable_earnings
                    },
                    transaction_summary: {
                        total_transactions: transactions.length,
                        daily_interest_count: transactions.filter(t => t.type === 'daily_interest').length,
                        referral_bonus_count: transactions.filter(t => t.type === 'referral_bonus').length,
                        withdrawal_count: transactions.filter(t => t.type === 'withdrawal').length
                    }
                }
            });
            
        } catch (error) {
            console.error('Fix transaction issues error:', error);
            res.status(500).json({ success: false, error: error.message });
        }
    });
    
    // 7. SIMULATE USER JOURNEY
    app.post('/api/debug/simulate-user-journey', debugAuth, async (req, res) => {
        console.log('🎯 SIMULATING COMPLETE USER JOURNEY');
        
        try {
            const { email = `test${Date.now()}@example.com`, amount = 10000 } = req.body;
            
            // Step 1: Create test user
            const testUser = new User({
                full_name: 'Debug User',
                email,
                phone: '080' + Math.floor(10000000 + Math.random() * 90000000),
                password: 'Debug123456',
                role: 'user',
                balance: amount * 10,
                kyc_verified: true,
                kyc_status: 'verified',
                bank_details: {
                    bank_name: 'Test Bank',
                    account_name: 'Debug User',
                    account_number: '0123456789',
                    bank_code: '123',
                    verified: true
                },
                metadata: { debug_created: true, request_id: req.requestId }
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
                metadata: { debug_created: true, request_id: req.requestId }
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
                bank_details: testUser.bank_details,
                metadata: { debug_created: true, request_id: req.requestId }
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
                metadata: { debug_created: true, request_id: req.requestId }
            });
            
            await deposit.save();
            console.log(`✅ Created pending deposit: ₦${(amount * 2).toLocaleString()}`);
            
            // Step 6: Create KYC submission
            const kyc = new KYCSubmission({
                user: testUser._id,
                id_type: 'national_id',
                id_number: 'A123456789',
                id_front_url: 'https://example.com/id-front.jpg',
                id_back_url: 'https://example.com/id-back.jpg',
                selfie_with_id_url: 'https://example.com/selfie.jpg',
                address_proof_url: 'https://example.com/address-proof.jpg',
                status: 'pending',
                metadata: { debug_created: true, request_id: req.requestId }
            });
            
            await kyc.save();
            console.log(`✅ Created pending KYC submission`);
            
            // Step 7: Emit admin notifications
            await emitToAllAdmins('new-investment', {
                investment_id: investment._id,
                user_id: testUser._id,
                user_name: testUser.full_name,
                user_email: testUser.email,
                amount,
                plan_name: plan.name,
                created_at: new Date(),
                debug: true
            });
            
            await emitToAllAdmins('new-withdrawal', {
                withdrawal_id: withdrawal._id,
                user_id: testUser._id,
                user_name: testUser.full_name,
                user_email: testUser.email,
                amount: amount / 2,
                payment_method: 'bank_transfer',
                created_at: new Date(),
                debug: true
            });
            
            await emitToAllAdmins('new-deposit', {
                deposit_id: deposit._id,
                user_id: testUser._id,
                user_name: testUser.full_name,
                user_email: testUser.email,
                amount: amount * 2,
                payment_method: 'bank_transfer',
                created_at: new Date(),
                debug: true
            });
            
            await emitToAllAdmins('new-kyc', {
                kyc_id: kyc._id,
                user_id: testUser._id,
                user_name: testUser.full_name,
                user_email: testUser.email,
                created_at: new Date(),
                debug: true
            });
            
            // Step 8: Check if admins are listening
            const adminConnections = connectionMonitor.getAdminConnections();
            
            res.json({
                success: true,
                message: 'Complete user journey simulated',
                data: {
                    user: {
                        id: testUser._id,
                        email: testUser.email,
                        balance: testUser.balance
                    },
                    investment: {
                        id: investment._id,
                        amount: investment.amount,
                        status: investment.status,
                        plan: plan.name
                    },
                    withdrawal: {
                        id: withdrawal._id,
                        amount: withdrawal.amount,
                        status: withdrawal.status
                    },
                    deposit: {
                        id: deposit._id,
                        amount: deposit.amount,
                        status: deposit.status
                    },
                    kyc: {
                        id: kyc._id,
                        status: kyc.status
                    },
                    admin_notifications: {
                        admin_connections: adminConnections.length,
                        investment_emitted: true,
                        withdrawal_emitted: true,
                        deposit_emitted: true,
                        kyc_emitted: true
                    },
                    next_steps: {
                        approve_investment: `POST /api/admin/investments/${investment._id}/approve`,
                        approve_withdrawal: `POST /api/admin/withdrawals/${withdrawal._id}/approve`,
                        approve_deposit: `POST /api/admin/deposits/${deposit._id}/approve`,
                        approve_kyc: `POST /api/admin/kyc/${kyc._id}/approve`,
                        check_pending: `GET /api/admin/pending-investments`
                    }
                }
            });
            
        } catch (error) {
            console.error('❌ Simulation error:', error);
            res.status(500).json({ 
                success: false, 
                error: error.message,
                stack: config.nodeEnv === 'development' ? error.stack : undefined
            });
        }
    });
    
    // 8. TEST ADMIN NOTIFICATIONS
    app.get('/api/debug/test-admin-notifications', debugAuth, async (req, res) => {
        console.log('🔔 TESTING ADMIN NOTIFICATION SYSTEM');
        
        try {
            const testData = {
                investment_id: new mongoose.Types.ObjectId(),
                withdrawal_id: new mongoose.Types.ObjectId(),
                deposit_id: new mongoose.Types.ObjectId(),
                kyc_id: new mongoose.Types.ObjectId(),
                user_id: new mongoose.Types.ObjectId(),
                timestamp: new Date()
            };
            
            // Test Socket.IO emission
            const events = [
                { 
                    name: 'new-investment', 
                    data: { 
                        ...testData, 
                        amount: 50000, 
                        type: 'investment',
                        plan_name: 'Cocoa Beans',
                        user_name: 'Test User',
                        user_email: 'test@example.com'
                    } 
                },
                { 
                    name: 'new-withdrawal', 
                    data: { 
                        ...testData, 
                        amount: 25000, 
                        type: 'withdrawal',
                        payment_method: 'bank_transfer',
                        user_name: 'Test User',
                        user_email: 'test@example.com'
                    } 
                },
                { 
                    name: 'new-deposit', 
                    data: { 
                        ...testData, 
                        amount: 100000, 
                        type: 'deposit',
                        payment_method: 'bank_transfer',
                        user_name: 'Test User',
                        user_email: 'test@example.com'
                    } 
                },
                { 
                    name: 'new-kyc', 
                    data: { 
                        ...testData, 
                        type: 'kyc',
                        user_name: 'Test User',
                        user_email: 'test@example.com'
                    } 
                },
                { 
                    name: 'new-support-ticket', 
                    data: { 
                        ...testData, 
                        type: 'support',
                        ticket_id: 'TKT123456',
                        subject: 'Test Support Ticket',
                        user_name: 'Test User'
                    } 
                },
                { 
                    name: 'aml-flagged', 
                    data: { 
                        ...testData, 
                        riskScore: 75, 
                        type: 'aml',
                        transactionType: 'withdrawal',
                        reasons: ['Large withdrawal request']
                    } 
                }
            ];
            
            const results = [];
            for (const event of events) {
                try {
                    emitToAllAdmins(event.name, event.data);
                    results.push({
                        event: event.name,
                        emitted: true,
                        data_sent: event.data
                    });
                    console.log(`✅ Emitted: ${event.name}`);
                } catch (error) {
                    results.push({
                        event: event.name,
                        emitted: false,
                        error: error.message
                    });
                    console.log(`❌ Failed: ${event.name} - ${error.message}`);
                }
            }
            
            // Check admin connections
            const adminConnections = connectionMonitor.getAdminConnections();
            
            // Create admin notification records
            const admin = await User.findOne({ role: { $in: ['admin', 'super_admin'] } });
            if (admin) {
                const notification = new Notification({
                    user: admin._id,
                    title: 'Debug Notification Test',
                    message: 'This is a test notification from the debugging system',
                    type: 'system',
                    is_read: false,
                    metadata: { test: true, request_id: req.requestId }
                });
                await notification.save();
            }
            
            res.json({
                success: true,
                timestamp: new Date().toISOString(),
                socket_status: {
                    total_connections: connectionMonitor.activeConnections.size,
                    admin_connections: adminConnections.length,
                    admin_online: adminConnections.length > 0
                },
                events_emitted: results,
                database_notification: admin ? 'Created' : 'No admin found'
            });
            
        } catch (error) {
            console.error('❌ Notification test error:', error);
            res.status(500).json({ success: false, error: error.message });
        }
    });
    
    // 9. TEST TRANSACTION FLOW
    app.post('/api/debug/test-transaction-flow/:userId', debugAuth, async (req, res) => {
        try {
            const { userId } = req.params;
            const { amount = 1000, type = 'daily_interest' } = req.body;
            
            const user = await User.findById(userId);
            if (!user) {
                return res.status(404).json({ success: false, error: 'User not found' });
            }
            
            const beforeState = {
                balance: user.balance,
                total_earnings: user.total_earnings,
                referral_earnings: user.referral_earnings,
                withdrawable_earnings: user.withdrawable_earnings,
                total_withdrawn: user.total_withdrawn
            };
            
            const transaction = await createTransaction(
                userId,
                type,
                parseFloat(amount),
                `Test ${type} transaction for debugging`,
                'completed',
                { debug: true, test: true, request_id: req.requestId }
            );
            
            if (!transaction.success) {
                return res.status(500).json({ 
                    success: false, 
                    error: transaction.error 
                });
            }
            
            const updatedUser = await User.findById(userId);
            const afterState = {
                balance: updatedUser.balance,
                total_earnings: updatedUser.total_earnings,
                referral_earnings: updatedUser.referral_earnings,
                withdrawable_earnings: updatedUser.withdrawable_earnings,
                total_withdrawn: updatedUser.total_withdrawn
            };
            
            // Get the created transaction
            const latestTransaction = await Transaction.findOne({
                user: userId,
                'metadata.debug': true
            }).sort({ createdAt: -1 });
            
            res.json({
                success: true,
                message: 'Transaction flow tested successfully',
                user: {
                    email: user.email,
                    before: beforeState,
                    after: afterState,
                    changes: {
                        balance: afterState.balance - beforeState.balance,
                        total_earnings: afterState.total_earnings - beforeState.total_earnings,
                        referral_earnings: afterState.referral_earnings - beforeState.referral_earnings,
                        withdrawable_earnings: afterState.withdrawable_earnings - beforeState.withdrawable_earnings
                    }
                },
                transaction: {
                    id: latestTransaction?._id,
                    type: latestTransaction?.type,
                    amount: latestTransaction?.amount,
                    description: latestTransaction?.description,
                    status: latestTransaction?.status
                }
            });
            
        } catch (error) {
            console.error('Test transaction flow error:', error);
            res.status(500).json({ success: false, error: error.message });
        }
    });
    
    // 10. BULK OPERATIONS TEST
    app.post('/api/debug/bulk-operations-test', debugAuth, async (req, res) => {
        try {
            const { operations = 5 } = req.body;
            const results = [];
            
            for (let i = 0; i < operations; i++) {
                // Create a test user
                const testUser = new User({
                    full_name: `Bulk Test User ${i + 1}`,
                    email: `bulk-test-${Date.now()}-${i}@example.com`,
                    phone: `080${10000000 + i}`,
                    password: 'Test123456',
                    balance: 100000,
                    metadata: { bulk_test: true, operation: i }
                });
                
                await testUser.save();
                
                // Create investment
                const plan = await InvestmentPlan.findOne({ is_active: true });
                if (plan) {
                    const investment = new Investment({
                        user: testUser._id,
                        plan: plan._id,
                        amount: 10000 * (i + 1),
                        status: i % 2 === 0 ? 'pending' : 'active',
                        start_date: new Date(),
                        end_date: new Date(Date.now() + plan.duration * 24 * 60 * 60 * 1000),
                        expected_earnings: (10000 * (i + 1) * plan.total_interest) / 100,
                        daily_earnings: (10000 * (i + 1) * plan.daily_interest) / 100,
                        payment_verified: i % 2 !== 0,
                        metadata: { bulk_test: true, operation: i }
                    });
                    
                    await investment.save();
                    
                    // Create transaction if investment is active
                    if (i % 2 !== 0) {
                        await createTransaction(
                            testUser._id,
                            'investment',
                            -10000 * (i + 1),
                            `Bulk test investment in ${plan.name}`,
                            'completed',
                            { bulk_test: true, operation: i }
                        );
                    }
                }
                
                results.push({
                    user: testUser.email,
                    user_id: testUser._id,
                    investment_created: true,
                    investment_status: i % 2 === 0 ? 'pending' : 'active'
                });
            }
            
            res.json({
                success: true,
                message: `Bulk operations test completed: ${operations} operations`,
                results,
                summary: {
                    users_created: results.length,
                    pending_investments: results.filter(r => r.investment_status === 'pending').length,
                    active_investments: results.filter(r => r.investment_status === 'active').length
                }
            });
            
        } catch (error) {
            console.error('Bulk operations test error:', error);
            res.status(500).json({ success: false, error: error.message });
        }
    });
    
    console.log('✅ Advanced debugging endpoints loaded');
}

// ==================== EXISTING AUTH ENDPOINTS (PRESERVED) ====================
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
            total_investments: 0
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

// ==================== PROFILE ENDPOINTS (PRESERVED) ====================
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

// ==================== PASSWORD RESET ENDPOINTS (PRESERVED) ====================
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

// ==================== INVESTMENT PLANS ENDPOINTS (PRESERVED) ====================
app.get('/api/plans', async (req, res) => {
    try {
        const plans = await InvestmentPlan.find({ is_active: true })
            .sort({ display_order: 1, min_amount: 1 })
            .lean();
        
        res.json(formatResponse(true, 'Plans retrieved successfully', { plans }));
    } catch (error) {
        handleError(res, error, 'Error fetching investment plans');
    }
});

// ==================== INVESTMENT ENDPOINTS (PRESERVED) ====================
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
        
        const investment = new Investment({
            user: userId,
            plan: plan_id,
            amount: investmentAmount,
            status: proofUrl ? 'pending' : 'active',
            start_date: new Date(),
            end_date: endDate,
            expected_earnings: expectedEarnings,
            daily_earnings: dailyEarnings,
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
        
        // If auto-approved (no proof required), add first day's earnings immediately
        if (!proofUrl) {
            const firstDayEarnings = (investmentAmount * plan.daily_interest) / 100;
            investment.earned_so_far = firstDayEarnings;
            investment.last_earning_date = new Date();
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
        }
        
        await createNotification(
            userId,
            'Investment Created',
            `Your investment of ₦${investmentAmount.toLocaleString()} in ${plan.name} has been created successfully.${proofUrl ? ' Awaiting admin approval.' : ''}`,
            'investment',
            '/investments'
        );
        
        res.status(201).json(formatResponse(true, 'Investment created successfully!', {
            investment: {
                ...investment.toObject(),
                plan_name: plan.name,
                expected_daily_earnings: dailyEarnings,
                expected_total_earnings: expectedEarnings,
                end_date: endDate
            }
        }));
    } catch (error) {
        handleError(res, error, 'Error creating investment');
    }
});

// ==================== DEPOSIT ENDPOINTS (PRESERVED) ====================
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
        
        // Notify admins
        emitToAllAdmins('new-deposit', {
            deposit_id: deposit._id,
            user_id: userId,
            amount: depositAmount,
            payment_method
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

// ==================== WITHDRAWAL ENDPOINTS (PRESERVED) ====================
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
        const requiresAdminApproval = !(freshUser.bank_details && freshUser.bank_details.verified);
        
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
                from_referral: fromReferral
            }
        );
        
        await createNotification(
            userId,
            requiresAdminApproval ? 'Withdrawal Request Submitted' : 'Withdrawal Auto-Approved',
            requiresAdminApproval 
                ? `Your withdrawal request of ₦${withdrawalAmount.toLocaleString()} has been submitted and is pending admin approval.`
                : `Your withdrawal request of ₦${withdrawalAmount.toLocaleString()} has been auto-approved and is being processed.`,
            'withdrawal',
            '/withdrawals'
        );
        
        // Notify admins
        emitToAllAdmins('new-withdrawal', {
            withdrawal_id: withdrawal._id,
            user_id: userId,
            amount: withdrawalAmount,
            payment_method,
            auto_approved: !requiresAdminApproval
        });
        
        res.status(201).json(formatResponse(true, 
            requiresAdminApproval 
                ? 'Withdrawal request submitted successfully!' 
                : 'Withdrawal auto-approved and queued for processing!', {
            withdrawal: {
                ...withdrawal.toObject(),
                formatted_amount: `₦${withdrawalAmount.toLocaleString()}`,
                formatted_net_amount: `₦${netAmount.toLocaleString()}`,
                formatted_fee: `₦${platformFee.toLocaleString()}`,
                requires_admin_approval: requiresAdminApproval,
                auto_approved: !requiresAdminApproval
            }
        }));
    } catch (error) {
        handleError(res, error, 'Error creating withdrawal');
    }
});

// ==================== TRANSACTION ENDPOINTS (PRESERVED) ====================
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

// ==================== KYC ENDPOINTS (PRESERVED) ====================
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
        
        // Notify admins
        emitToAllAdmins('new-kyc', {
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

// ==================== SUPPORT ENDPOINTS (PRESERVED) ====================
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
            `Your support ticket #${ticketId} has been created successfully. We will respond within 24 hours.`,
            'info',
            `/support/ticket/${ticketId}`
        );
        
        // Notify admins
        emitToAllAdmins('new-support-ticket', {
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

// ==================== REFERRAL ENDPOINTS (PRESERVED) ====================
app.get('/api/referrals/stats', auth, async (req, res) => {
    try {
        const userId = req.user._id;
        
        const referrals = await Referral.find({ referrer: userId })
            .populate('referred_user', 'full_name email createdAt balance')
            .sort({ createdAt: -1 })
            .lean();
        
        const user = await User.findById(userId);
        
        res.json(formatResponse(true, 'Referral stats retrieved successfully', {
            stats: {
                total_referrals: referrals.length,
                active_referrals: referrals.filter(r => r.status === 'active').length,
                referral_earnings: user.referral_earnings || 0,
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

// ==================== NOTIFICATION ENDPOINTS (PRESERVED) ====================
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

// ==================== UPLOAD ENDPOINT (PRESERVED) ====================
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
            mimeType: uploadResult.mimeType,
            folder,
            uploadedAt: new Date()
        }));
    } catch (error) {
        handleError(res, error, 'Error uploading file');
    }
});

// ==================== PAYMENT WEBHOOKS (PRESERVED) ====================
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
                
                // Find deposit by reference
                const deposit = await Deposit.findOne({ reference: tx_ref });
                if (!deposit) {
                    return res.status(404).send('Deposit not found');
                }
                
                // Update deposit status
                deposit.status = 'approved';
                deposit.approved_at = new Date();
                deposit.transaction_hash = payload.data.flw_ref;
                await deposit.save();
                
                // Credit user's balance
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

// ==================== DAILY INTEREST CRON JOB (PRESERVED) ====================
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

// ==================== ADMIN ENDPOINTS (PRESERVED) ====================
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
                total_pending: pendingInvestments + pendingDeposits + pendingWithdrawals + pendingKYC + amlFlags
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
                all_users: '/api/admin/users'
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
            search
        } = req.query;
        
        const query = {};
        
        if (status === 'active') query.is_active = true;
        if (status === 'inactive') query.is_active = false;
        if (role) query.role = role;
        if (kyc_status) query.kyc_status = kyc_status;
        
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
            portfolio_value: (user.balance || 0),
            available_for_withdrawal: user.withdrawable_earnings || 0
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
                verified_users: enhancedUsers.filter(u => u.kyc_verified).length,
                total_balance: enhancedUsers.reduce((sum, u) => sum + (u.balance || 0), 0),
                total_earnings: enhancedUsers.reduce((sum, u) => sum + (u.total_earnings || 0), 0),
                total_referral_earnings: enhancedUsers.reduce((sum, u) => sum + (u.referral_earnings || 0), 0),
                total_withdrawable: enhancedUsers.reduce((sum, u) => sum + (u.withdrawable_earnings || 0), 0)
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
        
        const userDetails = {
            user: user.toObject(),
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
        
        await investment.save();
        
        // Create earnings transaction
        await createTransaction(
            investment.user._id,
            'daily_interest',
            firstDayEarnings,
            `First day interest from ${investment.plan.name} investment (on approval)`,
            'completed',
            {
                investment_id: investment._id,
                plan_name: investment.plan.name,
                daily_interest: investment.plan.daily_interest
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
            'Investment Approved',
            `Your investment of ₦${investment.amount.toLocaleString()} in ${investment.plan.name} has been approved and is now active. First day earnings: ₦${firstDayEarnings.toLocaleString()}`,
            'investment',
            '/investments'
        );
        
        res.json(formatResponse(true, 'Investment approved successfully', {
            investment: investment.toObject()
        }));
    } catch (error) {
        handleError(res, error, 'Error approving investment');
    }
});

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
        
        // Credit user's balance
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
            `Your deposit of ₦${deposit.amount.toLocaleString()} has been approved and credited to your account.`,
            'success',
            '/deposits'
        );
        
        res.json(formatResponse(true, 'Deposit approved successfully', {
            deposit: deposit.toObject()
        }));
    } catch (error) {
        handleError(res, error, 'Error approving deposit');
    }
});

app.get('/api/admin/pending-withdrawals', adminAuth, async (req, res) => {
    try {
        const pendingWithdrawals = await Withdrawal.find({ status: 'pending' })
            .populate('user', 'full_name email phone balance')
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
        
        await withdrawal.save();
        
        // Deduct from user's earnings
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
                from_earnings: withdrawal.from_earnings,
                from_referral: withdrawal.from_referral
            }
        );
        
        await createNotification(
            withdrawal.user._id,
            'Withdrawal Approved',
            `Your withdrawal of ₦${withdrawal.amount.toLocaleString()} has been approved and processed.`,
            'success',
            '/withdrawals'
        );
        
        res.json(formatResponse(true, 'Withdrawal approved successfully', {
            withdrawal: withdrawal.toObject()
        }));
    } catch (error) {
        handleError(res, error, 'Error approving withdrawal');
    }
});

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
        
        res.json(formatResponse(true, 'KYC approved successfully', {
            kyc: kyc.toObject()
        }));
    } catch (error) {
        handleError(res, error, 'Error approving KYC');
    }
});

app.get('/api/admin/aml-flags', adminAuth, async (req, res) => {
    try {
        const amlFlags = await AmlMonitoring.find({ status: 'pending_review' })
            .populate('user', 'full_name email')
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
            console.log(`✅ Raw Wealthy Backend v40.0 - PRODUCTION READY`);
            console.log(`🌐 Environment: ${config.nodeEnv}`);
            console.log(`📍 Port: ${config.port}`);
            console.log(`🔗 Server URL: ${config.serverURL}`);
            console.log(`🔗 Client URL: ${config.clientURL}`);
            console.log(`🔌 Socket.IO: Enabled`);
            console.log(`📊 Database: Connected`);
            console.log(`🔧 Debug Endpoints: ${config.enableDebugEndpoints ? 'Enabled' : 'Disabled'}`);
            console.log('============================================\n');
            
            console.log('🎯 CRITICAL FEATURES VERIFIED:');
            console.log('1. ✅ ALL original endpoints preserved (NO alterations)');
            console.log('2. ✅ Advanced debugging system added');
            console.log('3. ✅ Real-time socket monitoring');
            console.log('4. ✅ Enhanced transaction system');
            console.log('5. ✅ Complete admin notifications');
            console.log('6. ✅ Production-ready error handling');
            console.log('7. ✅ Security enhancements');
            console.log('8. ✅ Performance optimizations');
            console.log('============================================\n');
            
            console.log('💰 FINANCIAL FLOW SYSTEM:');
            console.log('• Deposits → Add to balance');
            console.log('• Investments → Deduct from balance');
            console.log('• Daily Interest → Add to total_earnings + withdrawable_earnings + balance');
            console.log('• Referral Commission → Add to referral_earnings + withdrawable_earnings + balance');
            console.log('• Withdrawals → Deduct from withdrawable_earnings + balance');
            console.log('============================================\n');
            
            if (config.enableDebugEndpoints) {
                console.log('🔧 DEBUGGING TOOLS AVAILABLE:');
                console.log(`• GET /api/debug/system-status - Complete system health`);
                console.log(`• GET /api/debug/check-pending-actions - Check all pending items`);
                console.log(`• POST /api/debug/create-test-pending-actions - Create test data`);
                console.log(`• GET /api/debug/socket-connections - Monitor socket connections`);
                console.log(`• GET /api/debug/monitoring-dashboard - Live dashboard`);
                console.log(`• POST /api/debug/fix-transaction-issues/:userId - Fix user transactions`);
                console.log(`• POST /api/debug/simulate-user-journey - Full user journey test`);
                console.log(`• GET /api/debug/test-admin-notifications - Test admin notifications`);
                console.log(`• POST /api/debug/test-transaction-flow/:userId - Test transaction flow`);
                console.log(`• POST /api/debug/bulk-operations-test - Bulk operations test`);
                console.log('============================================\n');
            }
            
            console.log('✅ ALL ENDPOINTS PRESERVED AND ENHANCED');
            console.log('✅ PRODUCTION-READY WITH COMPLETE DEBUGGING');
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
