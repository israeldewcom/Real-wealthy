// server.js - Complete Production Backend
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
const compression = require('compression');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const nodemailer = require('nodemailer');

// Create necessary directories
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
    fs.mkdirSync(uploadsDir, { recursive: true });
}

// Initialize Express
const app = express();
const PORT = process.env.PORT || 10000;
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/raw-wealthy';

// Security middleware
app.use(helmet({
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false
}));
app.use(cors({
    origin: ['http://localhost:3000', 'http://127.0.0.1:5500', 'https://raw-wealthy.vercel.app'],
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
}));

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 1000,
    message: { success: false, message: 'Too many requests, please try again later.' }
});
app.use('/api/', limiter);

// Body parsing
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// Compression
app.use(compression());

// Logging
app.use(morgan('combined'));

// Static files
app.use('/uploads', express.static(uploadsDir));
app.use(express.static(path.join(__dirname, 'public')));

// MongoDB Connection with retry logic
const connectDB = async () => {
    try {
        await mongoose.connect(MONGODB_URI, {
            useNewUrlParser: true,
            useUnifiedTopology: true,
            serverSelectionTimeoutMS: 5000,
            socketTimeoutMS: 45000,
        });
        console.log('✅ MongoDB Connected Successfully');
        
        // Create indexes
        await mongoose.connection.db.collection('users').createIndex({ email: 1 }, { unique: true });
        await mongoose.connection.db.collection('users').createIndex({ phone: 1 }, { unique: true });
        await mongoose.connection.db.collection('users').createIndex({ referral_code: 1 }, { unique: true });
        
    } catch (error) {
        console.error('❌ MongoDB Connection Error:', error);
        // Try to connect with fallback
        setTimeout(connectDB, 5000);
    }
};

connectDB();

// File upload configuration
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, uploadsDir);
    },
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
    }
});

const fileFilter = (req, file, cb) => {
    const allowedTypes = /jpeg|jpg|png|gif|pdf/;
    const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
    const mimetype = allowedTypes.test(file.mimetype);
    
    if (mimetype && extname) {
        return cb(null, true);
    } else {
        cb(new Error('Only images and PDFs are allowed'));
    }
};

const upload = multer({ 
    storage: storage,
    fileFilter: fileFilter,
    limits: { fileSize: 5 * 1024 * 1024 } // 5MB
});

// Email transporter
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

// ==================== DATABASE MODELS ====================

// User Model
const userSchema = new mongoose.Schema({
    // Personal Information
    full_name: { type: String, required: true, trim: true },
    email: { type: String, required: true, unique: true, lowercase: true, trim: true },
    phone: { type: String, required: true, unique: true },
    password: { type: String, required: true, select: false },
    
    // Account Information
    role: { type: String, enum: ['user', 'admin', 'super_admin'], default: 'user' },
    is_active: { type: Boolean, default: true },
    is_email_verified: { type: Boolean, default: false },
    is_phone_verified: { type: Boolean, default: false },
    
    // Financial Information
    balance: { type: Number, default: 0, min: 0 },
    total_earnings: { type: Number, default: 0, min: 0 },
    total_invested: { type: Number, default: 0, min: 0 },
    total_withdrawn: { type: Number, default: 0, min: 0 },
    referral_earnings: { type: Number, default: 0, min: 0 },
    
    // Referral System
    referral_code: { type: String, unique: true, uppercase: true },
    referred_by: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    referral_count: { type: Number, default: 0 },
    
    // Investment Preferences
    risk_tolerance: { type: String, enum: ['low', 'medium', 'high'], default: 'medium' },
    investment_strategy: { type: String, enum: ['conservative', 'balanced', 'aggressive'], default: 'balanced' },
    
    // KYC Information
    kyc_status: { type: String, enum: ['pending', 'verified', 'rejected', 'not_submitted'], default: 'not_submitted' },
    kyc_documents: {
        id_type: String,
        id_number: String,
        id_front_url: String,
        id_back_url: String,
        selfie_with_id_url: String,
        verified_at: Date
    },
    
    // Bank Details
    bank_details: {
        bank_name: String,
        account_name: String,
        account_number: String,
        verified: { type: Boolean, default: false }
    },
    
    // Two-Factor Authentication
    two_factor_enabled: { type: Boolean, default: false },
    two_factor_secret: String,
    
    // Security
    password_reset_token: String,
    password_reset_expires: Date,
    email_verification_token: String,
    email_verification_expires: Date,
    last_login: Date,
    last_login_ip: String,
    
    // Timestamps
    created_at: { type: Date, default: Date.now },
    updated_at: { type: Date, default: Date.now }
}, { timestamps: { createdAt: 'created_at', updatedAt: 'updated_at' } });

// Hash password before saving
userSchema.pre('save', async function(next) {
    if (!this.isModified('password')) return next();
    this.password = await bcrypt.hash(this.password, 12);
    next();
});

// Generate referral code for new users
userSchema.pre('save', function(next) {
    if (this.isNew && !this.referral_code) {
        const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
        let code = '';
        for (let i = 0; i < 8; i++) {
            code += chars.charAt(Math.floor(Math.random() * chars.length));
        }
        this.referral_code = code;
    }
    next();
});

// Compare password method
userSchema.methods.comparePassword = async function(candidatePassword) {
    return await bcrypt.compare(candidatePassword, this.password);
};

// Create password reset token
userSchema.methods.createPasswordResetToken = function() {
    const resetToken = crypto.randomBytes(32).toString('hex');
    this.password_reset_token = crypto.createHash('sha256').update(resetToken).digest('hex');
    this.password_reset_expires = Date.now() + 10 * 60 * 1000; // 10 minutes
    return resetToken;
};

const User = mongoose.model('User', userSchema);

// Investment Plan Model
const investmentPlanSchema = new mongoose.Schema({
    name: { type: String, required: true, unique: true },
    description: { type: String, required: true },
    min_amount: { type: Number, required: true, min: 0 },
    max_amount: Number,
    daily_interest: { type: Number, required: true, min: 0, max: 100 },
    total_interest: { type: Number, required: true, min: 0 },
    duration: { type: Number, required: true, min: 1 },
    risk_level: { type: String, enum: ['low', 'medium', 'high'], default: 'medium' },
    category: { type: String, enum: ['cocoa', 'gold', 'oil', 'agriculture', 'mining', 'energy', 'precious_metals'], required: true },
    is_active: { type: Boolean, default: true },
    is_popular: { type: Boolean, default: false },
    referral_commission: { type: Number, default: 15, min: 0, max: 100 },
    platform_fee: { type: Number, default: 5, min: 0, max: 100 },
    total_investors: { type: Number, default: 0 },
    total_invested: { type: Number, default: 0 },
    total_earnings: { type: Number, default: 0 },
    color: { type: String, default: '#f59e0b' }
}, { timestamps: true });

investmentPlanSchema.methods.calculateDailyEarnings = function(investmentAmount) {
    return (investmentAmount * this.daily_interest) / 100;
};

investmentPlanSchema.methods.calculateTotalEarnings = function(investmentAmount) {
    return (investmentAmount * this.total_interest) / 100;
};

const InvestmentPlan = mongoose.model('InvestmentPlan', investmentPlanSchema);

// Investment Model
const investmentSchema = new mongoose.Schema({
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    plan: { type: mongoose.Schema.Types.ObjectId, ref: 'InvestmentPlan', required: true },
    amount: { type: Number, required: true, min: 0 },
    daily_interest: { type: Number, required: true },
    total_interest: { type: Number, required: true },
    daily_earnings: { type: Number, default: 0 },
    total_earned: { type: Number, default: 0 },
    expected_total: { type: Number, required: true },
    duration: { type: Number, required: true },
    start_date: { type: Date, default: Date.now },
    end_date: { type: Date, required: true },
    status: { type: String, enum: ['pending', 'active', 'completed', 'cancelled', 'suspended'], default: 'pending' },
    auto_renew: { type: Boolean, default: false },
    payment_proof_url: String,
    payment_proof_verified: { type: Boolean, default: false },
    last_payout: Date,
    next_payout: Date,
    payout_count: { type: Number, default: 0 },
    payout_days_completed: { type: Number, default: 0 },
    referral_commission_paid: { type: Boolean, default: false },
    referral_commission_amount: { type: Number, default: 0 },
    approved_by: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    approved_at: Date,
    rejected_by: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    rejected_at: Date,
    rejection_reason: String,
    created_at: { type: Date, default: Date.now }
}, { timestamps: true });

investmentSchema.virtual('remaining_days').get(function() {
    if (this.status !== 'active') return 0;
    const now = new Date();
    const end = new Date(this.end_date);
    const diff = Math.max(0, Math.ceil((end - now) / (1000 * 60 * 60 * 24)));
    return diff;
});

investmentSchema.virtual('days_elapsed').get(function() {
    const now = new Date();
    const start = new Date(this.start_date);
    const diff = Math.floor((now - start) / (1000 * 60 * 60 * 24));
    return Math.min(diff, this.duration);
});

const Investment = mongoose.model('Investment', investmentSchema);

// Transaction Model
const transactionSchema = new mongoose.Schema({
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    type: { type: String, enum: ['deposit', 'withdrawal', 'investment', 'earnings', 'referral', 'bonus', 'admin_credit', 'admin_debit', 'refund', 'transfer'], required: true },
    amount: { type: Number, required: true },
    description: { type: String, required: true },
    reference: { type: String, required: true, unique: true },
    status: { type: String, enum: ['pending', 'completed', 'failed', 'cancelled'], default: 'pending' },
    balance_before: Number,
    balance_after: Number,
    metadata: {
        investment_id: mongoose.Schema.Types.ObjectId,
        deposit_id: mongoose.Schema.Types.ObjectId,
        withdrawal_id: mongoose.Schema.Types.ObjectId,
        plan_name: String,
        payment_method: String,
        admin_id: mongoose.Schema.Types.ObjectId,
        remarks: String
    },
    created_at: { type: Date, default: Date.now }
}, { timestamps: true });

const Transaction = mongoose.model('Transaction', transactionSchema);

// Deposit Model
const depositSchema = new mongoose.Schema({
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    amount: { type: Number, required: true, min: 500 },
    payment_method: { type: String, enum: ['bank_transfer', 'crypto', 'paypal', 'card'], required: true },
    payment_proof_url: { type: String, required: true },
    status: { type: String, enum: ['pending', 'completed', 'rejected', 'cancelled'], default: 'pending' },
    transaction: { type: mongoose.Schema.Types.ObjectId, ref: 'Transaction' },
    processed_by: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    processed_at: Date,
    remarks: String,
    created_at: { type: Date, default: Date.now }
}, { timestamps: true });

const Deposit = mongoose.model('Deposit', depositSchema);

// Withdrawal Model
const withdrawalSchema = new mongoose.Schema({
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    amount: { type: Number, required: true, min: 1000 },
    platform_fee: { type: Number, default: 0 },
    net_amount: { type: Number, required: true },
    payment_method: { type: String, enum: ['bank_transfer', 'crypto', 'paypal'], required: true },
    status: { type: String, enum: ['pending', 'completed', 'rejected', 'cancelled'], default: 'pending' },
    transaction: { type: mongoose.Schema.Types.ObjectId, ref: 'Transaction' },
    transaction_id: String,
    processed_by: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    processed_at: Date,
    remarks: String,
    created_at: { type: Date, default: Date.now }
}, { timestamps: true });

const Withdrawal = mongoose.model('Withdrawal', withdrawalSchema);

// KYC Model
const kycSchema = new mongoose.Schema({
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    id_type: { type: String, enum: ['national_id', 'passport', 'driver_license'], required: true },
    id_number: { type: String, required: true },
    id_front_url: { type: String, required: true },
    id_back_url: String,
    selfie_with_id_url: { type: String, required: true },
    status: { type: String, enum: ['pending', 'approved', 'rejected'], default: 'pending' },
    reviewed_by: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    reviewed_at: Date,
    rejection_reason: String,
    created_at: { type: Date, default: Date.now }
}, { timestamps: true });

const KYC = mongoose.model('KYC', kycSchema);

// Referral Model
const referralSchema = new mongoose.Schema({
    referrer: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    referred_user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    status: { type: String, enum: ['pending', 'active', 'inactive'], default: 'pending' },
    commission_rate: { type: Number, default: 15 },
    earnings: { type: Number, default: 0 },
    created_at: { type: Date, default: Date.now }
}, { timestamps: true });

const Referral = mongoose.model('Referral', referralSchema);

// Support Ticket Model
const supportTicketSchema = new mongoose.Schema({
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    subject: { type: String, required: true },
    category: { type: String, enum: ['general', 'technical', 'investment', 'withdrawal', 'deposit', 'kyc', 'account'], required: true },
    message: { type: String, required: true },
    status: { type: String, enum: ['open', 'in_progress', 'resolved', 'closed'], default: 'open' },
    priority: { type: String, enum: ['low', 'medium', 'high', 'urgent'], default: 'medium' },
    attachments: [String],
    replies: [{
        user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
        message: String,
        is_admin: { type: Boolean, default: false },
        created_at: { type: Date, default: Date.now }
    }],
    resolved_by: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    resolved_at: Date,
    created_at: { type: Date, default: Date.now }
}, { timestamps: true });

const SupportTicket = mongoose.model('SupportTicket', supportTicketSchema);

// Notification Model
const notificationSchema = new mongoose.Schema({
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    title: { type: String, required: true },
    message: { type: String, required: true },
    type: { type: String, enum: ['info', 'success', 'warning', 'error'], default: 'info' },
    read: { type: Boolean, default: false },
    link: String,
    created_at: { type: Date, default: Date.now }
}, { timestamps: true });

const Notification = mongoose.model('Notification', notificationSchema);

// ==================== AUTHENTICATION MIDDLEWARE ====================

const protect = async (req, res, next) => {
    try {
        let token;
        if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
            token = req.headers.authorization.split(' ')[1];
        }

        if (!token) {
            return res.status(401).json({ success: false, message: 'Not authorized' });
        }

        const decoded = jwt.verify(token, process.env.JWT_SECRET || 'raw-wealthy-secret-key');
        const user = await User.findById(decoded.id).select('-password');

        if (!user) {
            return res.status(401).json({ success: false, message: 'User not found' });
        }

        if (!user.is_active) {
            return res.status(403).json({ success: false, message: 'Account deactivated' });
        }

        req.user = user;
        next();
    } catch (error) {
        console.error('Auth error:', error);
        res.status(401).json({ success: false, message: 'Invalid token' });
    }
};

const admin = (req, res, next) => {
    if (req.user.role !== 'admin' && req.user.role !== 'super_admin') {
        return res.status(403).json({ success: false, message: 'Admin access required' });
    }
    next();
};

// Generate JWT Token
const generateToken = (id) => {
    return jwt.sign({ id }, process.env.JWT_SECRET || 'raw-wealthy-secret-key', {
        expiresIn: '30d'
    });
};

// ==================== ROUTE HANDLERS ====================

// Health Check
app.get('/api/health', (req, res) => {
    res.json({
        success: true,
        message: 'Raw Wealthy API is running',
        timestamp: new Date(),
        uptime: process.uptime(),
        database: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected'
    });
});

// Debug Routes
app.get('/api/debug/paths', (req, res) => {
    const routes = [];
    app._router.stack.forEach((middleware) => {
        if (middleware.route) {
            routes.push({
                path: middleware.route.path,
                methods: Object.keys(middleware.route.methods)
            });
        }
    });
    res.json({ routes });
});

// ==================== AUTH ROUTES ====================

// Register
app.post('/api/auth/register', async (req, res) => {
    try {
        const { full_name, email, phone, password, referral_code, risk_tolerance, investment_strategy } = req.body;

        // Check if user exists
        const existingUser = await User.findOne({ 
            $or: [{ email: email.toLowerCase() }, { phone }] 
        });
        
        if (existingUser) {
            return res.status(400).json({
                success: false,
                message: 'User already exists'
            });
        }

        // Check referral code
        let referredBy = null;
        if (referral_code) {
            const referrer = await User.findOne({ referral_code: referral_code.toUpperCase() });
            if (referrer) {
                referredBy = referrer._id;
            }
        }

        // Create user
        const user = await User.create({
            full_name,
            email: email.toLowerCase(),
            phone,
            password,
            referred_by: referredBy,
            risk_tolerance: risk_tolerance || 'medium',
            investment_strategy: investment_strategy || 'balanced'
        });

        // Create referral record if applicable
        if (referredBy) {
            await Referral.create({
                referrer: referredBy,
                referred_user: user._id,
                status: 'pending'
            });

            // Update referrer's count
            await User.findByIdAndUpdate(referredBy, {
                $inc: { referral_count: 1 }
            });
        }

        // Generate token
        const token = generateToken(user._id);

        // Create welcome notification
        await Notification.create({
            user: user._id,
            title: 'Welcome to Raw Wealthy!',
            message: 'Your account has been created successfully. Start investing now!',
            type: 'success'
        });

        res.status(201).json({
            success: true,
            message: 'Registration successful',
            data: {
                token,
                user: {
                    _id: user._id,
                    full_name: user.full_name,
                    email: user.email,
                    phone: user.phone,
                    role: user.role,
                    balance: user.balance,
                    referral_code: user.referral_code,
                    kyc_status: user.kyc_status,
                    created_at: user.created_at
                }
            }
        });
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({
            success: false,
            message: 'Registration failed'
        });
    }
});

// Login
app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        const user = await User.findOne({ email: email.toLowerCase() }).select('+password');
        
        if (!user) {
            return res.status(401).json({
                success: false,
                message: 'Invalid credentials'
            });
        }

        const isPasswordValid = await user.comparePassword(password);
        if (!isPasswordValid) {
            return res.status(401).json({
                success: false,
                message: 'Invalid credentials'
            });
        }

        // Update last login
        user.last_login = new Date();
        user.last_login_ip = req.ip;
        await user.save();

        const token = generateToken(user._id);

        user.password = undefined;

        res.json({
            success: true,
            message: 'Login successful',
            data: {
                token,
                user: {
                    _id: user._id,
                    full_name: user.full_name,
                    email: user.email,
                    phone: user.phone,
                    role: user.role,
                    balance: user.balance,
                    kyc_status: user.kyc_status,
                    is_email_verified: user.is_email_verified,
                    is_phone_verified: user.is_phone_verified,
                    two_factor_enabled: user.two_factor_enabled,
                    referral_code: user.referral_code
                }
            }
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({
            success: false,
            message: 'Login failed'
        });
    }
});

// Get Profile
app.get('/api/profile', protect, async (req, res) => {
    try {
        const user = await User.findById(req.user.id)
            .select('-password -password_reset_token -email_verification_token');

        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        res.json({
            success: true,
            data: { user }
        });
    } catch (error) {
        console.error('Profile error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to get profile'
        });
    }
});

// Update Profile
app.put('/api/profile', protect, async (req, res) => {
    try {
        const { full_name, phone, country } = req.body;

        const user = await User.findByIdAndUpdate(
            req.user.id,
            { full_name, phone, country },
            { new: true, runValidators: true }
        ).select('-password');

        res.json({
            success: true,
            message: 'Profile updated successfully',
            data: { user }
        });
    } catch (error) {
        console.error('Update profile error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to update profile'
        });
    }
});

// Update Bank Details
app.put('/api/profile/bank', protect, async (req, res) => {
    try {
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
        ).select('-password');

        res.json({
            success: true,
            message: 'Bank details updated successfully',
            data: { user }
        });
    } catch (error) {
        console.error('Update bank error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to update bank details'
        });
    }
});

// ==================== INVESTMENT PLANS ====================

// Get all investment plans
app.get('/api/plans', async (req, res) => {
    try {
        const plans = await InvestmentPlan.find({ is_active: true })
            .sort({ min_amount: 1 });

        res.json({
            success: true,
            count: plans.length,
            data: { plans }
        });
    } catch (error) {
        console.error('Get plans error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch investment plans'
        });
    }
});

// Get single plan
app.get('/api/plans/:id', async (req, res) => {
    try {
        const plan = await InvestmentPlan.findById(req.params.id);

        if (!plan) {
            return res.status(404).json({
                success: false,
                message: 'Investment plan not found'
            });
        }

        res.json({
            success: true,
            data: { plan }
        });
    } catch (error) {
        console.error('Get plan error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch investment plan'
        });
    }
});

// ==================== DASHBOARD ====================

// Get dashboard stats
app.get('/api/dashboard/stats', protect, async (req, res) => {
    try {
        const userId = req.user.id;

        // Get user
        const user = await User.findById(userId);

        // Get investment stats
        const investmentStats = await Investment.aggregate([
            { $match: { user: user._id } },
            {
                $group: {
                    _id: null,
                    total_invested: { $sum: '$amount' },
                    total_earned: { $sum: '$total_earned' },
                    active_investments: { 
                        $sum: { $cond: [{ $eq: ['$status', 'active'] }, 1, 0] }
                    },
                    active_investment_value: {
                        $sum: { $cond: [{ $eq: ['$status', 'active'] }, '$amount', 0] }
                    }
                }
            }
        ]);

        // Get recent transactions
        const transactions = await Transaction.find({ user: userId })
            .sort({ created_at: -1 })
            .limit(5);

        // Get active investments
        const activeInvestments = await Investment.find({ 
            user: userId, 
            status: 'active' 
        })
        .populate('plan', 'name daily_interest total_interest duration color')
        .limit(5);

        const stats = investmentStats[0] || {
            total_invested: 0,
            total_earned: 0,
            active_investments: 0,
            active_investment_value: 0
        };

        // Generate sample earnings data for chart
        const earningsData = [];
        let totalDailyEarnings = 0;
        activeInvestments.forEach(inv => {
            totalDailyEarnings += (inv.amount * inv.daily_interest) / 100;
        });

        for (let i = 6; i >= 0; i--) {
            const date = new Date();
            date.setDate(date.getDate() - i);
            earningsData.push(Math.floor(totalDailyEarnings * (0.8 + Math.random() * 0.4)));
        }

        res.json({
            success: true,
            data: {
                user: {
                    balance: user.balance,
                    total_earnings: user.total_earnings,
                    referral_earnings: user.referral_earnings,
                    total_invested: user.total_invested,
                    total_withdrawn: user.total_withdrawn
                },
                dashboard_stats: {
                    ...stats,
                    daily_earnings: totalDailyEarnings
                },
                daily_earnings: earningsData,
                active_investments,
                recent_transactions: transactions
            }
        });
    } catch (error) {
        console.error('Dashboard stats error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to get dashboard stats'
        });
    }
});

// ==================== INVESTMENTS ====================

// Get user investments
app.get('/api/investments', protect, async (req, res) => {
    try {
        const { status, limit = 5 } = req.query;
        const userId = req.user.id;

        const query = { user: userId };
        if (status) {
            query.status = status;
        }

        const investments = await Investment.find(query)
            .populate('plan', 'name daily_interest total_interest duration color')
            .sort({ created_at: -1 })
            .limit(parseInt(limit));

        res.json({
            success: true,
            data: { investments }
        });
    } catch (error) {
        console.error('Get investments error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch investments'
        });
    }
});

// Create investment
app.post('/api/investments', protect, upload.single('payment_proof'), async (req, res) => {
    try {
        const { plan_id, amount, auto_renew } = req.body;
        const userId = req.user.id;

        // Get user
        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        // Check KYC status
        if (user.kyc_status !== 'verified') {
            return res.status(403).json({
                success: false,
                message: 'KYC verification required'
            });
        }

        // Get investment plan
        const plan = await InvestmentPlan.findById(plan_id);
        if (!plan || !plan.is_active) {
            return res.status(404).json({
                success: false,
                message: 'Investment plan not available'
            });
        }

        // Validate amount
        if (amount < plan.min_amount) {
            return res.status(400).json({
                success: false,
                message: `Minimum investment is ₦${plan.min_amount.toLocaleString()}`
            });
        }

        // Calculate end date
        const endDate = new Date();
        endDate.setDate(endDate.getDate() + plan.duration);

        // Calculate expected returns
        const dailyEarnings = plan.calculateDailyEarnings(amount);
        const totalEarnings = plan.calculateTotalEarnings(amount);
        const expectedTotal = amount + totalEarnings;

        // Create investment
        const investment = await Investment.create({
            user: userId,
            plan: plan_id,
            amount,
            daily_interest: plan.daily_interest,
            total_interest: plan.total_interest,
            daily_earnings: dailyEarnings,
            expected_total: expectedTotal,
            duration: plan.duration,
            end_date: endDate,
            auto_renew: auto_renew === 'true',
            payment_proof_url: req.file ? `/uploads/${req.file.filename}` : null,
            status: 'pending'
        });

        // Create transaction record
        await Transaction.create({
            user: userId,
            type: 'investment',
            amount: -amount,
            description: `Investment in ${plan.name} Plan`,
            reference: `INV${Date.now()}${Math.random().toString(36).substr(2, 5).toUpperCase()}`,
            status: 'pending',
            metadata: {
                investment_id: investment._id,
                plan_name: plan.name,
                duration: plan.duration
            }
        });

        // Create notification
        await Notification.create({
            user: userId,
            title: 'Investment Request Submitted',
            message: `Your investment of ₦${amount.toLocaleString()} in ${plan.name} has been submitted for approval.`,
            type: 'info'
        });

        res.status(201).json({
            success: true,
            message: 'Investment request submitted successfully',
            data: { investment }
        });
    } catch (error) {
        console.error('Create investment error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to create investment'
        });
    }
});

// Get investment stats
app.get('/api/investments/stats', protect, async (req, res) => {
    try {
        const userId = req.user.id;

        const stats = await Investment.aggregate([
            { $match: { user: userId } },
            {
                $group: {
                    _id: null,
                    total_invested: { $sum: '$amount' },
                    total_earned: { $sum: '$total_earned' },
                    active_investments: { 
                        $sum: { $cond: [{ $eq: ['$status', 'active'] }, 1, 0] }
                    },
                    completed_investments: { 
                        $sum: { $cond: [{ $eq: ['$status', 'completed'] }, 1, 0] }
                    },
                    active_investment_value: {
                        $sum: { $cond: [{ $eq: ['$status', 'active'] }, '$amount', 0] }
                    }
                }
            }
        ]);

        res.json({
            success: true,
            data: { 
                stats: stats[0] || {
                    total_invested: 0,
                    total_earned: 0,
                    active_investments: 0,
                    completed_investments: 0,
                    active_investment_value: 0
                }
            }
        });
    } catch (error) {
        console.error('Investment stats error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch investment statistics'
        });
    }
});

// Renew investment
app.post('/api/investments/:id/renew', protect, async (req, res) => {
    try {
        const investment = await Investment.findById(req.params.id)
            .populate('plan');

        if (!investment) {
            return res.status(404).json({
                success: false,
                message: 'Investment not found'
            });
        }

        if (investment.user.toString() !== req.user.id) {
            return res.status(403).json({
                success: false,
                message: 'Not authorized'
            });
        }

        if (investment.status !== 'completed') {
            return res.status(400).json({
                success: false,
                message: 'Only completed investments can be renewed'
            });
        }

        if (!investment.auto_renew) {
            return res.status(400).json({
                success: false,
                message: 'Auto renew is not enabled'
            });
        }

        const plan = investment.plan;
        const newEndDate = new Date();
        newEndDate.setDate(newEndDate.getDate() + plan.duration);

        const newInvestment = await Investment.create({
            user: req.user.id,
            plan: investment.plan._id,
            amount: investment.amount,
            daily_interest: plan.daily_interest,
            total_interest: plan.total_interest,
            daily_earnings: plan.calculateDailyEarnings(investment.amount),
            expected_total: investment.amount + plan.calculateTotalEarnings(investment.amount),
            duration: plan.duration,
            end_date: newEndDate,
            auto_renew: investment.auto_renew,
            status: 'active'
        });

        investment.renewed_at = new Date();
        await investment.save();

        res.json({
            success: true,
            message: 'Investment renewed successfully',
            data: { investment: newInvestment }
        });
    } catch (error) {
        console.error('Renew investment error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to renew investment'
        });
    }
});

// ==================== TRANSACTIONS ====================

// Get user transactions
app.get('/api/transactions', protect, async (req, res) => {
    try {
        const { limit = 5 } = req.query;
        const userId = req.user.id;

        const transactions = await Transaction.find({ user: userId })
            .sort({ created_at: -1 })
            .limit(parseInt(limit));

        res.json({
            success: true,
            data: { transactions }
        });
    } catch (error) {
        console.error('Get transactions error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch transactions'
        });
    }
});

// Get single transaction
app.get('/api/transactions/:id', protect, async (req, res) => {
    try {
        const transaction = await Transaction.findOne({
            _id: req.params.id,
            user: req.user.id
        });

        if (!transaction) {
            return res.status(404).json({
                success: false,
                message: 'Transaction not found'
            });
        }

        res.json({
            success: true,
            data: { transaction }
        });
    } catch (error) {
        console.error('Get transaction error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch transaction'
        });
    }
});

// ==================== DEPOSITS ====================

// Get user deposits
app.get('/api/deposits', protect, async (req, res) => {
    try {
        const { status, limit = 10 } = req.query;
        const userId = req.user.id;

        const query = { user: userId };
        if (status) {
            query.status = status;
        }

        const deposits = await Deposit.find(query)
            .sort({ created_at: -1 })
            .limit(parseInt(limit));

        res.json({
            success: true,
            data: { deposits }
        });
    } catch (error) {
        console.error('Get deposits error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch deposits'
        });
    }
});

// Create deposit
app.post('/api/deposits', protect, upload.single('payment_proof'), async (req, res) => {
    try {
        const { amount, payment_method } = req.body;
        const userId = req.user.id;

        if (amount < 500) {
            return res.status(400).json({
                success: false,
                message: 'Minimum deposit is ₦500'
            });
        }

        if (!req.file) {
            return res.status(400).json({
                success: false,
                message: 'Payment proof is required'
            });
        }

        const deposit = await Deposit.create({
            user: userId,
            amount,
            payment_method,
            payment_proof_url: `/uploads/${req.file.filename}`,
            status: 'pending'
        });

        // Create transaction
        await Transaction.create({
            user: userId,
            type: 'deposit',
            amount: amount,
            description: `Deposit via ${payment_method}`,
            reference: `DEP${Date.now()}${Math.random().toString(36).substr(2, 5).toUpperCase()}`,
            status: 'pending',
            metadata: {
                deposit_id: deposit._id,
                payment_method: payment_method
            }
        });

        // Create notification
        await Notification.create({
            user: userId,
            title: 'Deposit Request Submitted',
            message: `Your deposit of ₦${amount.toLocaleString()} has been submitted for approval.`,
            type: 'info'
        });

        res.status(201).json({
            success: true,
            message: 'Deposit request submitted successfully',
            data: { deposit }
        });
    } catch (error) {
        console.error('Create deposit error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to create deposit'
        });
    }
});

// Cancel deposit
app.post('/api/deposits/:id/cancel', protect, async (req, res) => {
    try {
        const deposit = await Deposit.findOne({
            _id: req.params.id,
            user: req.user.id,
            status: 'pending'
        });

        if (!deposit) {
            return res.status(404).json({
                success: false,
                message: 'Deposit not found or cannot be cancelled'
            });
        }

        deposit.status = 'cancelled';
        await deposit.save();

        await Transaction.findOneAndUpdate(
            { metadata: { deposit_id: deposit._id } },
            { status: 'cancelled' }
        );

        res.json({
            success: true,
            message: 'Deposit cancelled successfully'
        });
    } catch (error) {
        console.error('Cancel deposit error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to cancel deposit'
        });
    }
});

// ==================== WITHDRAWALS ====================

// Get user withdrawals
app.get('/api/withdrawals', protect, async (req, res) => {
    try {
        const { status, limit = 10 } = req.query;
        const userId = req.user.id;

        const query = { user: userId };
        if (status) {
            query.status = status;
        }

        const withdrawals = await Withdrawal.find(query)
            .sort({ created_at: -1 })
            .limit(parseInt(limit));

        res.json({
            success: true,
            data: { withdrawals }
        });
    } catch (error) {
        console.error('Get withdrawals error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch withdrawals'
        });
    }
});

// Create withdrawal
app.post('/api/withdrawals', protect, async (req, res) => {
    try {
        const { amount, payment_method } = req.body;
        const userId = req.user.id;

        // Validate amount
        if (amount < 1000) {
            return res.status(400).json({
                success: false,
                message: 'Minimum withdrawal is ₦1000'
            });
        }

        // Get user
        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        // Check balance
        if (user.balance < amount) {
            return res.status(400).json({
                success: false,
                message: 'Insufficient balance'
            });
        }

        // Calculate platform fee (5%)
        const platformFee = amount * 0.05;
        const netAmount = amount - platformFee;

        // Create withdrawal
        const withdrawal = await Withdrawal.create({
            user: userId,
            amount,
            platform_fee: platformFee,
            net_amount: netAmount,
            payment_method,
            status: 'pending'
        });

        // Create transaction
        await Transaction.create({
            user: userId,
            type: 'withdrawal',
            amount: -amount,
            description: `Withdrawal via ${payment_method}`,
            reference: `WTH${Date.now()}${Math.random().toString(36).substr(2, 5).toUpperCase()}`,
            status: 'pending',
            balance_before: user.balance,
            balance_after: user.balance - amount,
            metadata: {
                withdrawal_id: withdrawal._id,
                payment_method: payment_method,
                platform_fee: platformFee,
                net_amount: netAmount
            }
        });

        // Update user balance
        user.balance -= amount;
        user.total_withdrawn += amount;
        await user.save();

        // Create notification
        await Notification.create({
            user: userId,
            title: 'Withdrawal Request Submitted',
            message: `Your withdrawal of ₦${amount.toLocaleString()} has been submitted for processing.`,
            type: 'info'
        });

        res.status(201).json({
            success: true,
            message: 'Withdrawal request submitted successfully',
            data: { withdrawal }
        });
    } catch (error) {
        console.error('Create withdrawal error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to create withdrawal'
        });
    }
});

// Cancel withdrawal
app.post('/api/withdrawals/:id/cancel', protect, async (req, res) => {
    try {
        const withdrawal = await Withdrawal.findOne({
            _id: req.params.id,
            user: req.user.id,
            status: 'pending'
        });

        if (!withdrawal) {
            return res.status(404).json({
                success: false,
                message: 'Withdrawal not found or cannot be cancelled'
            });
        }

        // Get user
        const user = await User.findById(req.user.id);

        // Refund amount
        user.balance += withdrawal.amount;
        user.total_withdrawn -= withdrawal.amount;
        await user.save();

        withdrawal.status = 'cancelled';
        await withdrawal.save();

        await Transaction.findOneAndUpdate(
            { metadata: { withdrawal_id: withdrawal._id } },
            { status: 'cancelled' }
        );

        res.json({
            success: true,
            message: 'Withdrawal cancelled successfully'
        });
    } catch (error) {
        console.error('Cancel withdrawal error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to cancel withdrawal'
        });
    }
});

// ==================== KYC ====================

// Get KYC status
app.get('/api/kyc/status', protect, async (req, res) => {
    try {
        const user = await User.findById(req.user.id);
        
        const latestKYC = await KYC.findOne({ user: req.user.id })
            .sort({ created_at: -1 });

        res.json({
            success: true,
            data: {
                status: user.kyc_status,
                kyc: latestKYC
            }
        });
    } catch (error) {
        console.error('KYC status error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to get KYC status'
        });
    }
});

// Submit KYC
app.post('/api/kyc', protect, upload.fields([
    { name: 'id_front', maxCount: 1 },
    { name: 'id_back', maxCount: 1 },
    { name: 'selfie_with_id', maxCount: 1 }
]), async (req, res) => {
    try {
        const { id_type, id_number } = req.body;
        const files = req.files;

        if (!files || !files.id_front || !files.selfie_with_id) {
            return res.status(400).json({
                success: false,
                message: 'Required documents missing'
            });
        }

        // Create KYC record
        const kyc = await KYC.create({
            user: req.user.id,
            id_type,
            id_number,
            id_front_url: `/uploads/${files.id_front[0].filename}`,
            id_back_url: files.id_back ? `/uploads/${files.id_back[0].filename}` : null,
            selfie_with_id_url: `/uploads/${files.selfie_with_id[0].filename}`,
            status: 'pending'
        });

        // Update user KYC status
        await User.findByIdAndUpdate(req.user.id, {
            kyc_status: 'pending',
            kyc_documents: {
                id_type,
                id_number,
                id_front_url: `/uploads/${files.id_front[0].filename}`,
                id_back_url: files.id_back ? `/uploads/${files.id_back[0].filename}` : null,
                selfie_with_id_url: `/uploads/${files.selfie_with_id[0].filename}`
            }
        });

        // Create notification
        await Notification.create({
            user: req.user.id,
            title: 'KYC Submitted',
            message: 'Your KYC documents have been submitted for verification.',
            type: 'info'
        });

        res.status(201).json({
            success: true,
            message: 'KYC submitted successfully',
            data: { kyc }
        });
    } catch (error) {
        console.error('KYC submission error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to submit KYC'
        });
    }
});

// Get KYC details
app.get('/api/kyc/:id', protect, async (req, res) => {
    try {
        const kyc = await KYC.findOne({
            _id: req.params.id,
            user: req.user.id
        });

        if (!kyc) {
            return res.status(404).json({
                success: false,
                message: 'KYC record not found'
            });
        }

        res.json({
            success: true,
            data: { kyc }
        });
    } catch (error) {
        console.error('Get KYC error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch KYC details'
        });
    }
});

// ==================== SUPPORT ====================

// Get support tickets
app.get('/api/support/tickets', protect, async (req, res) => {
    try {
        const tickets = await SupportTicket.find({ user: req.user.id })
            .sort({ created_at: -1 });

        res.json({
            success: true,
            data: { tickets }
        });
    } catch (error) {
        console.error('Get tickets error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch support tickets'
        });
    }
});

// Create support ticket
app.post('/api/support', protect, async (req, res) => {
    try {
        const { subject, category, message } = req.body;

        const ticket = await SupportTicket.create({
            user: req.user.id,
            subject,
            category,
            message,
            status: 'open'
        });

        // Create notification
        await Notification.create({
            user: req.user.id,
            title: 'Support Ticket Created',
            message: `Your support ticket "${subject}" has been created.`,
            type: 'info'
        });

        res.status(201).json({
            success: true,
            message: 'Support ticket created successfully',
            data: { ticket }
        });
    } catch (error) {
        console.error('Create ticket error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to create support ticket'
        });
    }
});

// Get single ticket
app.get('/api/support/tickets/:id', protect, async (req, res) => {
    try {
        const ticket = await SupportTicket.findOne({
            _id: req.params.id,
            user: req.user.id
        });

        if (!ticket) {
            return res.status(404).json({
                success: false,
                message: 'Ticket not found'
            });
        }

        res.json({
            success: true,
            data: { ticket }
        });
    } catch (error) {
        console.error('Get ticket error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch ticket'
        });
    }
});

// Add reply to ticket
app.post('/api/support/tickets/:id/reply', protect, async (req, res) => {
    try {
        const { message } = req.body;

        const ticket = await SupportTicket.findOne({
            _id: req.params.id,
            user: req.user.id
        });

        if (!ticket) {
            return res.status(404).json({
                success: false,
                message: 'Ticket not found'
            });
        }

        ticket.replies.push({
            user: req.user.id,
            message,
            is_admin: false
        });

        await ticket.save();

        res.json({
            success: true,
            message: 'Reply added successfully',
            data: { ticket }
        });
    } catch (error) {
        console.error('Add reply error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to add reply'
        });
    }
});

// ==================== REFERRALS ====================

// Get referral stats
app.get('/api/referrals/stats', protect, async (req, res) => {
    try {
        const referrals = await Referral.find({ referrer: req.user.id });
        const activeReferrals = referrals.filter(r => r.status === 'active');

        const stats = {
            total_referrals: referrals.length,
            active_referrals: activeReferrals.length,
            total_earnings: referrals.reduce((sum, r) => sum + r.earnings, 0),
            pending_earnings: referrals
                .filter(r => r.status === 'pending')
                .reduce((sum, r) => sum + r.earnings, 0)
        };

        res.json({
            success: true,
            data: { stats }
        });
    } catch (error) {
        console.error('Referral stats error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch referral stats'
        });
    }
});

// Get referral list
app.get('/api/referrals/list', protect, async (req, res) => {
    try {
        const referrals = await Referral.find({ referrer: req.user.id })
            .populate('referred_user', 'full_name email created_at')
            .sort({ created_at: -1 });

        res.json({
            success: true,
            data: { referrals }
        });
    } catch (error) {
        console.error('Referral list error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch referral list'
        });
    }
});

// Get referral earnings
app.get('/api/referrals/earnings', protect, async (req, res) => {
    try {
        const referrals = await Referral.find({ referrer: req.user.id });
        
        const earnings = referrals.map(r => ({
            date: r.created_at,
            amount: r.earnings,
            status: r.status,
            referred_user: r.referred_user
        }));

        res.json({
            success: true,
            data: { earnings }
        });
    } catch (error) {
        console.error('Referral earnings error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch referral earnings'
        });
    }
});

// ==================== ADMIN ROUTES ====================

// Get admin dashboard stats
app.get('/api/admin/dashboard', protect, admin, async (req, res) => {
    try {
        const totalUsers = await User.countDocuments();
        const totalInvestments = await Investment.countDocuments();
        const totalDeposits = await Deposit.countDocuments();
        const totalWithdrawals = await Withdrawal.countDocuments();
        
        const totalInvested = await Investment.aggregate([
            { $match: { status: { $in: ['active', 'completed'] } } },
            { $group: { _id: null, total: { $sum: '$amount' } } }
        ]);

        const totalEarnings = await Investment.aggregate([
            { $match: { status: 'completed' } },
            { $group: { _id: null, total: { $sum: '$total_earned' } } }
        ]);

        const pendingInvestments = await Investment.countDocuments({ status: 'pending' });
        const pendingDeposits = await Deposit.countDocuments({ status: 'pending' });
        const pendingWithdrawals = await Withdrawal.countDocuments({ status: 'pending' });
        const pendingKYC = await KYC.countDocuments({ status: 'pending' });

        const stats = {
            total_users: totalUsers,
            total_investments: totalInvestments,
            total_deposits: totalDeposits,
            total_withdrawals: totalWithdrawals,
            total_invested: totalInvested[0]?.total || 0,
            total_earnings: totalEarnings[0]?.total || 0,
            platform_earnings: (totalInvested[0]?.total || 0) * 0.05, // 5% platform fee
            pending_requests: pendingInvestments + pendingDeposits + pendingWithdrawals + pendingKYC,
            active_investments: await Investment.countDocuments({ status: 'active' })
        };

        res.json({
            success: true,
            data: { stats }
        });
    } catch (error) {
        console.error('Admin dashboard error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch admin dashboard stats'
        });
    }
});

// Get all users
app.get('/api/admin/users', protect, admin, async (req, res) => {
    try {
        const { page = 1, limit = 10, search = '' } = req.query;
        const skip = (parseInt(page) - 1) * parseInt(limit);

        const query = {};
        if (search) {
            query.$or = [
                { full_name: { $regex: search, $options: 'i' } },
                { email: { $regex: search, $options: 'i' } },
                { phone: { $regex: search, $options: 'i' } }
            ];
        }

        const users = await User.find(query)
            .select('-password')
            .skip(skip)
            .limit(parseInt(limit))
            .sort({ created_at: -1 });

        const total = await User.countDocuments(query);

        res.json({
            success: true,
            data: {
                users,
                pagination: {
                    page: parseInt(page),
                    limit: parseInt(limit),
                    total,
                    pages: Math.ceil(total / parseInt(limit))
                }
            }
        });
    } catch (error) {
        console.error('Admin users error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch users'
        });
    }
});

// Get single user
app.get('/api/admin/users/:id', protect, admin, async (req, res) => {
    try {
        const user = await User.findById(req.params.id).select('-password');

        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        // Get user investments
        const investments = await Investment.find({ user: user._id })
            .populate('plan')
            .sort({ created_at: -1 });

        // Get user transactions
        const transactions = await Transaction.find({ user: user._id })
            .sort({ created_at: -1 })
            .limit(10);

        res.json({
            success: true,
            data: {
                user,
                investments,
                transactions
            }
        });
    } catch (error) {
        console.error('Admin user error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch user'
        });
    }
});

// Update user
app.put('/api/admin/users/:id', protect, admin, async (req, res) => {
    try {
        const { full_name, email, phone, role, is_active, balance } = req.body;

        const user = await User.findByIdAndUpdate(
            req.params.id,
            {
                full_name,
                email: email.toLowerCase(),
                phone,
                role,
                is_active,
                balance: parseFloat(balance) || 0
            },
            { new: true, runValidators: true }
        ).select('-password');

        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        res.json({
            success: true,
            message: 'User updated successfully',
            data: { user }
        });
    } catch (error) {
        console.error('Admin update user error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to update user'
        });
    }
});

// Adjust user balance
app.post('/api/admin/users/:id/adjust-balance', protect, admin, async (req, res) => {
    try {
        const { amount, type, remarks } = req.body;
        const userId = req.params.id;

        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        const adjustmentAmount = parseFloat(amount);
        if (isNaN(adjustmentAmount)) {
            return res.status(400).json({
                success: false,
                message: 'Invalid amount'
            });
        }

        const oldBalance = user.balance;
        if (type === 'credit') {
            user.balance += adjustmentAmount;
        } else if (type === 'debit') {
            user.balance -= adjustmentAmount;
            if (user.balance < 0) user.balance = 0;
        } else {
            return res.status(400).json({
                success: false,
                message: 'Invalid adjustment type'
            });
        }

        await user.save();

        // Create transaction
        await Transaction.create({
            user: userId,
            type: type === 'credit' ? 'admin_credit' : 'admin_debit',
            amount: type === 'credit' ? adjustmentAmount : -adjustmentAmount,
            description: `Admin balance adjustment: ${remarks || 'No remarks'}`,
            reference: `ADJ${Date.now()}${Math.random().toString(36).substr(2, 5).toUpperCase()}`,
            status: 'completed',
            balance_before: oldBalance,
            balance_after: user.balance,
            metadata: {
                admin_id: req.user.id,
                remarks: remarks
            }
        });

        // Create notification for user
        await Notification.create({
            user: userId,
            title: 'Balance Adjusted',
            message: `Your balance has been ${type === 'credit' ? 'credited' : 'debited'} by ₦${adjustmentAmount.toLocaleString()}.`,
            type: type === 'credit' ? 'success' : 'warning'
        });

        res.json({
            success: true,
            message: 'Balance adjusted successfully',
            data: {
                old_balance: oldBalance,
                new_balance: user.balance,
                adjustment: adjustmentAmount,
                type: type
            }
        });
    } catch (error) {
        console.error('Adjust balance error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to adjust balance'
        });
    }
});

// Get pending investments
app.get('/api/admin/pending-investments', protect, admin, async (req, res) => {
    try {
        const investments = await Investment.find({ status: 'pending' })
            .populate('user', 'full_name email phone')
            .populate('plan', 'name min_amount duration')
            .sort({ created_at: -1 });

        res.json({
            success: true,
            data: { investments }
        });
    } catch (error) {
        console.error('Pending investments error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch pending investments'
        });
    }
});

// Approve investment
app.post('/api/admin/investments/:id/approve', protect, admin, async (req, res) => {
    try {
        const investment = await Investment.findById(req.params.id)
            .populate('user')
            .populate('plan');

        if (!investment) {
            return res.status(404).json({
                success: false,
                message: 'Investment not found'
            });
        }

        if (investment.status !== 'pending') {
            return res.status(400).json({
                success: false,
                message: 'Investment is not pending'
            });
        }

        // Update investment status
        investment.status = 'active';
        investment.approved_by = req.user.id;
        investment.approved_at = new Date();
        investment.payment_proof_verified = true;
        await investment.save();

        // Update user total invested
        await User.findByIdAndUpdate(investment.user._id, {
            $inc: { total_invested: investment.amount }
        });

        // Update plan statistics
        await InvestmentPlan.findByIdAndUpdate(investment.plan._id, {
            $inc: {
                total_investors: 1,
                total_invested: investment.amount
            }
        });

        // Update transaction status
        await Transaction.findOneAndUpdate(
            { metadata: { investment_id: investment._id } },
            { status: 'completed' }
        );

        // Handle referral commission
        if (investment.user.referred_by) {
            const commission = investment.amount * (investment.plan.referral_commission || 15) / 100;
            
            // Update referrer's earnings
            await User.findByIdAndUpdate(investment.user.referred_by, {
                $inc: {
                    referral_earnings: commission,
                    balance: commission
                }
            });

            // Update referral record
            await Referral.findOneAndUpdate(
                { referrer: investment.user.referred_by, referred_user: investment.user._id },
                {
                    $set: { status: 'active' },
                    $inc: { earnings: commission }
                }
            );

            // Create transaction for referrer
            await Transaction.create({
                user: investment.user.referred_by,
                type: 'referral',
                amount: commission,
                description: `Referral commission from ${investment.user.full_name}`,
                reference: `REF${Date.now()}${Math.random().toString(36).substr(2, 5).toUpperCase()}`,
                status: 'completed',
                metadata: {
                    investment_id: investment._id,
                    referred_user_id: investment.user._id,
                    commission_rate: investment.plan.referral_commission || 15
                }
            });

            investment.referral_commission_paid = true;
            investment.referral_commission_amount = commission;
            await investment.save();
        }

        // Create notification for user
        await Notification.create({
            user: investment.user._id,
            title: 'Investment Approved',
            message: `Your investment of ₦${investment.amount.toLocaleString()} in ${investment.plan.name} has been approved and is now active.`,
            type: 'success'
        });

        res.json({
            success: true,
            message: 'Investment approved successfully',
            data: { investment }
        });
    } catch (error) {
        console.error('Approve investment error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to approve investment'
        });
    }
});

// Reject investment
app.post('/api/admin/investments/:id/reject', protect, admin, async (req, res) => {
    try {
        const { remarks } = req.body;
        const investment = await Investment.findById(req.params.id)
            .populate('user');

        if (!investment) {
            return res.status(404).json({
                success: false,
                message: 'Investment not found'
            });
        }

        if (investment.status !== 'pending') {
            return res.status(400).json({
                success: false,
                message: 'Investment is not pending'
            });
        }

        // Update investment status
        investment.status = 'cancelled';
        investment.rejected_by = req.user.id;
        investment.rejected_at = new Date();
        investment.rejection_reason = remarks;
        await investment.save();

        // Refund amount to user
        await User.findByIdAndUpdate(investment.user._id, {
            $inc: { balance: investment.amount }
        });

        // Update transaction status
        await Transaction.findOneAndUpdate(
            { metadata: { investment_id: investment._id } },
            { 
                status: 'failed',
                metadata: { remarks: remarks }
            }
        );

        // Create notification for user
        await Notification.create({
            user: investment.user._id,
            title: 'Investment Rejected',
            message: `Your investment of ₦${investment.amount.toLocaleString()} has been rejected. Reason: ${remarks}`,
            type: 'error'
        });

        res.json({
            success: true,
            message: 'Investment rejected successfully',
            data: { investment }
        });
    } catch (error) {
        console.error('Reject investment error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to reject investment'
        });
    }
});

// Get pending deposits
app.get('/api/admin/pending-deposits', protect, admin, async (req, res) => {
    try {
        const deposits = await Deposit.find({ status: 'pending' })
            .populate('user', 'full_name email phone')
            .sort({ created_at: -1 });

        res.json({
            success: true,
            data: { deposits }
        });
    } catch (error) {
        console.error('Pending deposits error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch pending deposits'
        });
    }
});

// Approve deposit
app.post('/api/admin/deposits/:id/approve', protect, admin, async (req, res) => {
    try {
        const deposit = await Deposit.findById(req.params.id)
            .populate('user');

        if (!deposit) {
            return res.status(404).json({
                success: false,
                message: 'Deposit not found'
            });
        }

        if (deposit.status !== 'pending') {
            return res.status(400).json({
                success: false,
                message: 'Deposit is not pending'
            });
        }

        // Update deposit status
        deposit.status = 'completed';
        deposit.processed_by = req.user.id;
        deposit.processed_at = new Date();
        await deposit.save();

        // Update user balance
        await User.findByIdAndUpdate(deposit.user._id, {
            $inc: { balance: deposit.amount }
        });

        // Update transaction status
        await Transaction.findOneAndUpdate(
            { metadata: { deposit_id: deposit._id } },
            { 
                status: 'completed',
                balance_after: deposit.user.balance + deposit.amount
            }
        );

        // Create notification for user
        await Notification.create({
            user: deposit.user._id,
            title: 'Deposit Approved',
            message: `Your deposit of ₦${deposit.amount.toLocaleString()} has been approved and credited to your account.`,
            type: 'success'
        });

        res.json({
            success: true,
            message: 'Deposit approved successfully',
            data: { deposit }
        });
    } catch (error) {
        console.error('Approve deposit error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to approve deposit'
        });
    }
});

// Reject deposit
app.post('/api/admin/deposits/:id/reject', protect, admin, async (req, res) => {
    try {
        const { remarks } = req.body;
        const deposit = await Deposit.findById(req.params.id)
            .populate('user');

        if (!deposit) {
            return res.status(404).json({
                success: false,
                message: 'Deposit not found'
            });
        }

        if (deposit.status !== 'pending') {
            return res.status(400).json({
                success: false,
                message: 'Deposit is not pending'
            });
        }

        // Update deposit status
        deposit.status = 'rejected';
        deposit.processed_by = req.user.id;
        deposit.processed_at = new Date();
        deposit.remarks = remarks;
        await deposit.save();

        // Update transaction status
        await Transaction.findOneAndUpdate(
            { metadata: { deposit_id: deposit._id } },
            { 
                status: 'failed',
                metadata: { remarks: remarks }
            }
        );

        // Create notification for user
        await Notification.create({
            user: deposit.user._id,
            title: 'Deposit Rejected',
            message: `Your deposit of ₦${deposit.amount.toLocaleString()} has been rejected. Reason: ${remarks}`,
            type: 'error'
        });

        res.json({
            success: true,
            message: 'Deposit rejected successfully',
            data: { deposit }
        });
    } catch (error) {
        console.error('Reject deposit error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to reject deposit'
        });
    }
});

// Get pending withdrawals
app.get('/api/admin/pending-withdrawals', protect, admin, async (req, res) => {
    try {
        const withdrawals = await Withdrawal.find({ status: 'pending' })
            .populate('user', 'full_name email phone')
            .sort({ created_at: -1 });

        res.json({
            success: true,
            data: { withdrawals }
        });
    } catch (error) {
        console.error('Pending withdrawals error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch pending withdrawals'
        });
    }
});

// Approve withdrawal
app.post('/api/admin/withdrawals/:id/approve', protect, admin, async (req, res) => {
    try {
        const { transaction_id } = req.body;
        const withdrawal = await Withdrawal.findById(req.params.id)
            .populate('user');

        if (!withdrawal) {
            return res.status(404).json({
                success: false,
                message: 'Withdrawal not found'
            });
        }

        if (withdrawal.status !== 'pending') {
            return res.status(400).json({
                success: false,
                message: 'Withdrawal is not pending'
            });
        }

        // Update withdrawal status
        withdrawal.status = 'completed';
        withdrawal.processed_by = req.user.id;
        withdrawal.processed_at = new Date();
        withdrawal.transaction_id = transaction_id;
        await withdrawal.save();

        // Update transaction status
        await Transaction.findOneAndUpdate(
            { metadata: { withdrawal_id: withdrawal._id } },
            { 
                status: 'completed',
                metadata: { transaction_id: transaction_id }
            }
        );

        // Create notification for user
        await Notification.create({
            user: withdrawal.user._id,
            title: 'Withdrawal Approved',
            message: `Your withdrawal of ₦${withdrawal.amount.toLocaleString()} has been approved and processed.`,
            type: 'success'
        });

        res.json({
            success: true,
            message: 'Withdrawal approved successfully',
            data: { withdrawal }
        });
    } catch (error) {
        console.error('Approve withdrawal error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to approve withdrawal'
        });
    }
});

// Reject withdrawal
app.post('/api/admin/withdrawals/:id/reject', protect, admin, async (req, res) => {
    try {
        const { remarks } = req.body;
        const withdrawal = await Withdrawal.findById(req.params.id)
            .populate('user');

        if (!withdrawal) {
            return res.status(404).json({
                success: false,
                message: 'Withdrawal not found'
            });
        }

        if (withdrawal.status !== 'pending') {
            return res.status(400).json({
                success: false,
                message: 'Withdrawal is not pending'
            });
        }

        // Update withdrawal status
        withdrawal.status = 'rejected';
        withdrawal.processed_by = req.user.id;
        withdrawal.processed_at = new Date();
        withdrawal.remarks = remarks;
        await withdrawal.save();

        // Refund amount to user (since it was deducted when withdrawal was created)
        await User.findByIdAndUpdate(withdrawal.user._id, {
            $inc: { balance: withdrawal.amount },
            $inc: { total_withdrawn: -withdrawal.amount }
        });

        // Update transaction status
        await Transaction.findOneAndUpdate(
            { metadata: { withdrawal_id: withdrawal._id } },
            { 
                status: 'failed',
                metadata: { remarks: remarks }
            }
        );

        // Create notification for user
        await Notification.create({
            user: withdrawal.user._id,
            title: 'Withdrawal Rejected',
            message: `Your withdrawal of ₦${withdrawal.amount.toLocaleString()} has been rejected. Reason: ${remarks}`,
            type: 'error'
        });

        res.json({
            success: true,
            message: 'Withdrawal rejected successfully',
            data: { withdrawal }
        });
    } catch (error) {
        console.error('Reject withdrawal error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to reject withdrawal'
        });
    }
});

// Get pending KYC
app.get('/api/admin/pending-kyc', protect, admin, async (req, res) => {
    try {
        const kycList = await KYC.find({ status: 'pending' })
            .populate('user', 'full_name email phone created_at')
            .sort({ created_at: -1 });

        res.json({
            success: true,
            data: { kyc: kycList }
        });
    } catch (error) {
        console.error('Pending KYC error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch pending KYC'
        });
    }
});

// Approve KYC
app.post('/api/admin/kyc/:id/approve', protect, admin, async (req, res) => {
    try {
        const kyc = await KYC.findById(req.params.id)
            .populate('user');

        if (!kyc) {
            return res.status(404).json({
                success: false,
                message: 'KYC not found'
            });
        }

        if (kyc.status !== 'pending') {
            return res.status(400).json({
                success: false,
                message: 'KYC is not pending'
            });
        }

        // Update KYC status
        kyc.status = 'approved';
        kyc.reviewed_by = req.user.id;
        kyc.reviewed_at = new Date();
        await kyc.save();

        // Update user KYC status
        await User.findByIdAndUpdate(kyc.user._id, {
            kyc_status: 'verified',
            'kyc_documents.verified_at': new Date()
        });

        // Create notification for user
        await Notification.create({
            user: kyc.user._id,
            title: 'KYC Approved',
            message: 'Your KYC verification has been approved. You can now make investments.',
            type: 'success'
        });

        res.json({
            success: true,
            message: 'KYC approved successfully',
            data: { kyc }
        });
    } catch (error) {
        console.error('Approve KYC error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to approve KYC'
        });
    }
});

// Reject KYC
app.post('/api/admin/kyc/:id/reject', protect, admin, async (req, res) => {
    try {
        const { rejection_reason } = req.body;
        const kyc = await KYC.findById(req.params.id)
            .populate('user');

        if (!kyc) {
            return res.status(404).json({
                success: false,
                message: 'KYC not found'
            });
        }

        if (kyc.status !== 'pending') {
            return res.status(400).json({
                success: false,
                message: 'KYC is not pending'
            });
        }

        // Update KYC status
        kyc.status = 'rejected';
        kyc.reviewed_by = req.user.id;
        kyc.reviewed_at = new Date();
        kyc.rejection_reason = rejection_reason;
        await kyc.save();

        // Update user KYC status
        await User.findByIdAndUpdate(kyc.user._id, {
            kyc_status: 'rejected'
        });

        // Create notification for user
        await Notification.create({
            user: kyc.user._id,
            title: 'KYC Rejected',
            message: `Your KYC verification has been rejected. Reason: ${rejection_reason}. Please submit new documents.`,
            type: 'error'
        });

        res.json({
            success: true,
            message: 'KYC rejected successfully',
            data: { kyc }
        });
    } catch (error) {
        console.error('Reject KYC error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to reject KYC'
        });
    }
});

// Send notification
app.post('/api/admin/notifications/send', protect, admin, async (req, res) => {
    try {
        const { title, message, type, user_id, send_to_all } = req.body;

        if (send_to_all) {
            // Send to all users
            const users = await User.find({ role: 'user' });
            const notifications = users.map(user => ({
                user: user._id,
                title,
                message,
                type: type || 'info'
            }));

            await Notification.insertMany(notifications);
        } else if (user_id) {
            // Send to specific user
            await Notification.create({
                user: user_id,
                title,
                message,
                type: type || 'info'
            });
        } else {
            return res.status(400).json({
                success: false,
                message: 'Either user_id or send_to_all is required'
            });
        }

        res.json({
            success: true,
            message: 'Notification sent successfully'
        });
    } catch (error) {
        console.error('Send notification error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to send notification'
        });
    }
});

// Get admin logs
app.get('/api/admin/logs', protect, admin, async (req, res) => {
    try {
        const { type, limit = 50 } = req.query;
        
        const query = {};
        if (type) {
            query.type = type;
        }

        // Get admin actions from transactions
        const adminTransactions = await Transaction.find({
            type: { $in: ['admin_credit', 'admin_debit'] }
        })
        .populate('user', 'full_name email')
        .sort({ created_at: -1 })
        .limit(parseInt(limit));

        // Get KYC approvals/rejections
        const kycActions = await KYC.find({
            reviewed_by: { $exists: true }
        })
        .populate('user', 'full_name email')
        .populate('reviewed_by', 'full_name')
        .sort({ reviewed_at: -1 })
        .limit(parseInt(limit));

        // Get investment approvals/rejections
        const investmentActions = await Investment.find({
            $or: [{ approved_by: { $exists: true } }, { rejected_by: { $exists: true } }]
        })
        .populate('user', 'full_name email')
        .populate('approved_by', 'full_name')
        .populate('rejected_by', 'full_name')
        .sort({ updated_at: -1 })
        .limit(parseInt(limit));

        res.json({
            success: true,
            data: {
                admin_transactions: adminTransactions,
                kyc_actions: kycActions,
                investment_actions: investmentActions
            }
        });
    } catch (error) {
        console.error('Admin logs error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch admin logs'
        });
    }
});

// ==================== WALLET ====================

// Get wallet
app.get('/api/wallet', protect, async (req, res) => {
    try {
        const user = await User.findById(req.user.id).select('balance bank_details');

        const wallet = {
            balance: user.balance,
            bank_details: user.bank_details,
            currency: 'NGN'
        };

        res.json({
            success: true,
            data: { wallet }
        });
    } catch (error) {
        console.error('Get wallet error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch wallet'
        });
    }
});

// Transfer funds
app.post('/api/wallet/transfer', protect, async (req, res) => {
    try {
        const { to_user_id, amount, remarks } = req.body;

        if (amount <= 0) {
            return res.status(400).json({
                success: false,
                message: 'Invalid amount'
            });
        }

        const fromUser = await User.findById(req.user.id);
        const toUser = await User.findById(to_user_id);

        if (!toUser) {
            return res.status(404).json({
                success: false,
                message: 'Recipient not found'
            });
        }

        if (fromUser.balance < amount) {
            return res.status(400).json({
                success: false,
                message: 'Insufficient balance'
            });
        }

        // Update balances
        fromUser.balance -= amount;
        toUser.balance += amount;

        await fromUser.save();
        await toUser.save();

        // Create transactions
        await Transaction.create({
            user: req.user.id,
            type: 'transfer',
            amount: -amount,
            description: `Transfer to ${toUser.full_name}: ${remarks || 'No remarks'}`,
            reference: `TRF${Date.now()}${Math.random().toString(36).substr(2, 5).toUpperCase()}`,
            status: 'completed',
            balance_before: fromUser.balance + amount,
            balance_after: fromUser.balance,
            metadata: {
                to_user_id: toUser._id,
                remarks: remarks
            }
        });

        await Transaction.create({
            user: toUser._id,
            type: 'transfer',
            amount: amount,
            description: `Transfer from ${fromUser.full_name}: ${remarks || 'No remarks'}`,
            reference: `TRF${Date.now()}${Math.random().toString(36).substr(2, 5).toUpperCase()}`,
            status: 'completed',
            balance_before: toUser.balance - amount,
            balance_after: toUser.balance,
            metadata: {
                from_user_id: req.user.id,
                remarks: remarks
            }
        });

        // Create notifications
        await Notification.create({
            user: req.user.id,
            title: 'Transfer Sent',
            message: `You transferred ₦${amount.toLocaleString()} to ${toUser.full_name}.`,
            type: 'info'
        });

        await Notification.create({
            user: toUser._id,
            title: 'Transfer Received',
            message: `You received ₦${amount.toLocaleString()} from ${fromUser.full_name}.`,
            type: 'success'
        });

        res.json({
            success: true,
            message: 'Transfer completed successfully',
            data: {
                amount: amount,
                recipient: toUser.full_name,
                new_balance: fromUser.balance
            }
        });
    } catch (error) {
        console.error('Transfer error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to transfer funds'
        });
    }
});

// Get wallet transactions
app.get('/api/wallet/transactions', protect, async (req, res) => {
    try {
        const transactions = await Transaction.find({ user: req.user.id })
            .sort({ created_at: -1 })
            .limit(50);

        res.json({
            success: true,
            data: { transactions }
        });
    } catch (error) {
        console.error('Wallet transactions error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch wallet transactions'
        });
    }
});

// ==================== NOTIFICATIONS ====================

// Get notifications
app.get('/api/notifications', protect, async (req, res) => {
    try {
        const notifications = await Notification.find({ user: req.user.id })
            .sort({ created_at: -1 })
            .limit(20);

        res.json({
            success: true,
            data: { notifications }
        });
    } catch (error) {
        console.error('Get notifications error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch notifications'
        });
    }
});

// Mark notification as read
app.post('/api/notifications/:id/read', protect, async (req, res) => {
    try {
        await Notification.findByIdAndUpdate(req.params.id, { read: true });

        res.json({
            success: true,
            message: 'Notification marked as read'
        });
    } catch (error) {
        console.error('Mark notification error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to mark notification as read'
        });
    }
});

// Delete notification
app.delete('/api/notifications/:id', protect, async (req, res) => {
    try {
        await Notification.findOneAndDelete({
            _id: req.params.id,
            user: req.user.id
        });

        res.json({
            success: true,
            message: 'Notification deleted'
        });
    } catch (error) {
        console.error('Delete notification error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to delete notification'
        });
    }
});

// ==================== FILE UPLOAD ====================

app.post('/api/upload', protect, upload.single('file'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({
                success: false,
                message: 'No file uploaded'
            });
        }

        res.json({
            success: true,
            message: 'File uploaded successfully',
            data: {
                fileUrl: `/uploads/${req.file.filename}`,
                filename: req.file.filename,
                originalname: req.file.originalname,
                size: req.file.size,
                mimetype: req.file.mimetype
            }
        });
    } catch (error) {
        console.error('Upload error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to upload file'
        });
    }
});

// ==================== OTHER AUTH ROUTES ====================

// Forgot password
app.post('/api/auth/forgot-password', async (req, res) => {
    try {
        const { email } = req.body;

        const user = await User.findOne({ email: email.toLowerCase() });
        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        const resetToken = user.createPasswordResetToken();
        await user.save();

        // Send email in production
        console.log('Password reset token:', resetToken);

        res.json({
            success: true,
            message: 'Password reset instructions sent to your email'
        });
    } catch (error) {
        console.error('Forgot password error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to process password reset'
        });
    }
});

// Reset password
app.post('/api/auth/reset-password/:token', async (req, res) => {
    try {
        const { token } = req.params;
        const { password } = req.body;

        const hashedToken = crypto.createHash('sha256').update(token).digest('hex');

        const user = await User.findOne({
            password_reset_token: hashedToken,
            password_reset_expires: { $gt: Date.now() }
        }).select('+password');

        if (!user) {
            return res.status(400).json({
                success: false,
                message: 'Invalid or expired reset token'
            });
        }

        user.password = password;
        user.password_reset_token = undefined;
        user.password_reset_expires = undefined;
        await user.save();

        const newToken = generateToken(user._id);

        res.json({
            success: true,
            message: 'Password reset successfully',
            data: {
                token: newToken
            }
        });
    } catch (error) {
        console.error('Reset password error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to reset password'
        });
    }
});

// Change password
app.post('/api/auth/change-password', protect, async (req, res) => {
    try {
        const { current_password, new_password } = req.body;
        const user = await User.findById(req.user.id).select('+password');

        const isPasswordValid = await user.comparePassword(current_password);
        if (!isPasswordValid) {
            return res.status(401).json({
                success: false,
                message: 'Current password is incorrect'
            });
        }

        user.password = new_password;
        await user.save();

        res.json({
            success: true,
            message: 'Password changed successfully'
        });
    } catch (error) {
        console.error('Change password error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to change password'
        });
    }
});

// Enable 2FA
app.post('/api/auth/two-factor/enable', protect, async (req, res) => {
    try {
        const user = await User.findById(req.user.id);
        
        if (user.two_factor_enabled) {
            return res.status(400).json({
                success: false,
                message: '2FA is already enabled'
            });
        }

        const secret = crypto.randomBytes(20).toString('hex');
        user.two_factor_secret = secret;
        await user.save();

        res.json({
            success: true,
            message: '2FA enabled successfully',
            data: {
                secret: secret,
                qrCodeUrl: `otpauth://totp/RawWealthy:${user.email}?secret=${secret}&issuer=RawWealthy`
            }
        });
    } catch (error) {
        console.error('Enable 2FA error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to enable 2FA'
        });
    }
});

// Verify 2FA
app.post('/api/auth/two-factor/verify', protect, async (req, res) => {
    try {
        const { code } = req.body;
        const user = await User.findById(req.user.id);

        if (!code || code.length !== 6 || !/^\d+$/.test(code)) {
            return res.status(400).json({
                success: false,
                message: 'Invalid 2FA code'
            });
        }

        user.two_factor_enabled = true;
        await user.save();

        res.json({
            success: true,
            message: '2FA verified and enabled'
        });
    } catch (error) {
        console.error('Verify 2FA error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to verify 2FA'
        });
    }
});

// Disable 2FA
app.post('/api/auth/two-factor/disable', protect, async (req, res) => {
    try {
        const { password } = req.body;
        const user = await User.findById(req.user.id).select('+password');

        const isPasswordValid = await user.comparePassword(password);
        if (!isPasswordValid) {
            return res.status(401).json({
                success: false,
                message: 'Password is incorrect'
            });
        }

        user.two_factor_enabled = false;
        user.two_factor_secret = undefined;
        await user.save();

        res.json({
            success: true,
            message: '2FA disabled successfully'
        });
    } catch (error) {
        console.error('Disable 2FA error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to disable 2FA'
        });
    }
});

// Verify email
app.get('/api/auth/verify-email/:token', async (req, res) => {
    try {
        const { token } = req.params;

        const hashedToken = crypto.createHash('sha256').update(token).digest('hex');

        const user = await User.findOne({
            email_verification_token: hashedToken,
            email_verification_expires: { $gt: Date.now() }
        });

        if (!user) {
            return res.status(400).json({
                success: false,
                message: 'Invalid or expired verification token'
            });
        }

        user.is_email_verified = true;
        user.email_verification_token = undefined;
        user.email_verification_expires = undefined;
        await user.save();

        res.json({
            success: true,
            message: 'Email verified successfully'
        });
    } catch (error) {
        console.error('Email verification error:', error);
        res.status(500).json({
            success: false,
            message: 'Email verification failed'
        });
    }
});

// Verify phone
app.post('/api/auth/verify-phone', protect, async (req, res) => {
    try {
        const { phone, code } = req.body;

        const user = await User.findOne({ phone });
        
        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        user.is_phone_verified = true;
        await user.save();

        res.json({
            success: true,
            message: 'Phone verified successfully'
        });
    } catch (error) {
        console.error('Phone verification error:', error);
        res.status(500).json({
            success: false,
            message: 'Phone verification failed'
        });
    }
});

// Resend verification
app.post('/api/auth/resend-verification', async (req, res) => {
    try {
        const { email } = req.body;

        const user = await User.findOne({ email: email.toLowerCase() });
        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        if (user.is_email_verified) {
            return res.status(400).json({
                success: false,
                message: 'Email already verified'
            });
        }

        const verificationToken = crypto.randomBytes(32).toString('hex');
        user.email_verification_token = crypto.createHash('sha256').update(verificationToken).digest('hex');
        user.email_verification_expires = Date.now() + 24 * 60 * 60 * 1000;
        await user.save();

        res.json({
            success: true,
            message: 'Verification email sent successfully'
        });
    } catch (error) {
        console.error('Resend verification error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to resend verification email'
        });
    }
});

// ==================== SEED DATABASE ====================

// Seed initial data
app.get('/api/seed', async (req, res) => {
    try {
        // Clear existing data
        await User.deleteMany({});
        await InvestmentPlan.deleteMany({});
        await Investment.deleteMany({});
        await Transaction.deleteMany({});
        await Deposit.deleteMany({});
        await Withdrawal.deleteMany({});
        await KYC.deleteMany({});
        await Referral.deleteMany({});
        await SupportTicket.deleteMany({});
        await Notification.deleteMany({});

        // Create admin user
        const admin = await User.create({
            full_name: 'Admin User',
            email: 'admin@rawwealthy.com',
            phone: '+2348123456789',
            password: 'Admin123!',
            role: 'super_admin',
            is_email_verified: true,
            is_phone_verified: true,
            kyc_status: 'verified',
            balance: 1000000,
            referral_code: 'ADMIN001'
        });

        // Create regular user
        const user = await User.create({
            full_name: 'John Doe',
            email: 'john@example.com',
            phone: '+2348123456790',
            password: 'Password123!',
            role: 'user',
            is_email_verified: true,
            is_phone_verified: true,
            kyc_status: 'verified',
            balance: 500000,
            referred_by: admin._id
        });

        // Create investment plans
        const plans = [
            {
                name: 'Cocoa Beans',
                description: 'Invest in premium cocoa beans with stable returns',
                min_amount: 3500,
                daily_interest: 2.5,
                total_interest: 75,
                duration: 30,
                risk_level: 'low',
                category: 'cocoa',
                is_popular: true,
                is_active: true,
                referral_commission: 15,
                platform_fee: 5,
                color: '#f59e0b'
            },
            {
                name: 'Gold',
                description: 'Precious metal investment with high liquidity',
                min_amount: 50000,
                daily_interest: 3.2,
                total_interest: 96,
                duration: 30,
                risk_level: 'medium',
                category: 'gold',
                is_popular: true,
                is_active: true,
                referral_commission: 15,
                platform_fee: 5,
                color: '#ffd700'
            },
            {
                name: 'Crude Oil',
                description: 'Energy sector investment with premium returns',
                min_amount: 100000,
                daily_interest: 4.1,
                total_interest: 123,
                duration: 30,
                risk_level: 'high',
                category: 'oil',
                is_popular: false,
                is_active: true,
                referral_commission: 15,
                platform_fee: 5,
                color: '#000000'
            },
            {
                name: 'Agricultural Produce',
                description: 'Investment in various agricultural products',
                min_amount: 10000,
                daily_interest: 2.8,
                total_interest: 84,
                duration: 30,
                risk_level: 'medium',
                category: 'agriculture',
                is_popular: true,
                is_active: true,
                referral_commission: 15,
                platform_fee: 5,
                color: '#10b981'
            },
            {
                name: 'Precious Metals',
                description: 'Diversified precious metals portfolio',
                min_amount: 75000,
                daily_interest: 3.5,
                total_interest: 105,
                duration: 30,
                risk_level: 'medium',
                category: 'precious_metals',
                is_popular: false,
                is_active: true,
                referral_commission: 15,
                platform_fee: 5,
                color: '#8b5cf6'
            }
        ];

        await InvestmentPlan.insertMany(plans);

        // Create some sample investments
        const cocoaPlan = await InvestmentPlan.findOne({ name: 'Cocoa Beans' });
        const goldPlan = await InvestmentPlan.findOne({ name: 'Gold' });

        if (cocoaPlan && goldPlan) {
            // Active investment
            await Investment.create({
                user: user._id,
                plan: cocoaPlan._id,
                amount: 50000,
                daily_interest: cocoaPlan.daily_interest,
                total_interest: cocoaPlan.total_interest,
                daily_earnings: cocoaPlan.calculateDailyEarnings(50000),
                expected_total: 50000 + cocoaPlan.calculateTotalEarnings(50000),
                duration: cocoaPlan.duration,
                start_date: new Date(Date.now() - 15 * 24 * 60 * 60 * 1000), // 15 days ago
                end_date: new Date(Date.now() + 15 * 24 * 60 * 60 * 1000), // 15 days from now
                status: 'active',
                auto_renew: true,
                total_earned: 18750, // 15 days of earnings
                payout_days_completed: 15
            });

            // Completed investment
            await Investment.create({
                user: user._id,
                plan: goldPlan._id,
                amount: 100000,
                daily_interest: goldPlan.daily_interest,
                total_interest: goldPlan.total_interest,
                daily_earnings: goldPlan.calculateDailyEarnings(100000),
                expected_total: 100000 + goldPlan.calculateTotalEarnings(100000),
                duration: goldPlan.duration,
                start_date: new Date(Date.now() - 45 * 24 * 60 * 60 * 1000), // 45 days ago
                end_date: new Date(Date.now() - 15 * 24 * 60 * 60 * 1000), // 15 days ago
                status: 'completed',
                auto_renew: false,
                total_earned: 96000, // Full earnings
                payout_days_completed: 30
            });
        }

        // Create sample transactions
        await Transaction.create({
            user: user._id,
            type: 'deposit',
            amount: 500000,
            description: 'Initial deposit via bank transfer',
            reference: 'DEP123456789',
            status: 'completed',
            balance_before: 0,
            balance_after: 500000,
            metadata: {
                payment_method: 'bank_transfer'
            }
        });

        await Transaction.create({
            user: user._id,
            type: 'investment',
            amount: -50000,
            description: 'Investment in Cocoa Beans Plan',
            reference: 'INV123456789',
            status: 'completed',
            balance_before: 500000,
            balance_after: 450000,
            metadata: {
                investment_id: (await Investment.findOne({ user: user._id, status: 'active' }))._id,
                plan_name: 'Cocoa Beans'
            }
        });

        await Transaction.create({
            user: user._id,
            type: 'earnings',
            amount: 1250,
            description: 'Daily earnings from Cocoa Beans investment',
            reference: 'ERN123456789',
            status: 'completed',
            balance_before: 450000,
            balance_after: 451250,
            metadata: {
                investment_id: (await Investment.findOne({ user: user._id, status: 'active' }))._id
            }
        });

        // Create referral record
        await Referral.create({
            referrer: admin._id,
            referred_user: user._id,
            status: 'active',
            commission_rate: 15,
            earnings: 7500 // 15% of 50000
        });

        // Create sample notifications
        await Notification.create({
            user: user._id,
            title: 'Welcome to Raw Wealthy!',
            message: 'Your account has been created successfully. Start investing now!',
            type: 'success',
            read: true
        });

        await Notification.create({
            user: user._id,
            title: 'Investment Active',
            message: 'Your investment in Cocoa Beans Plan is now active and earning daily returns.',
            type: 'success'
        });

        await Notification.create({
            user: user._id,
            title: 'New Feature Available',
            message: 'Check out our new investment plans with higher returns!',
            type: 'info'
        });

        res.json({
            success: true,
            message: 'Database seeded successfully',
            data: {
                admin: {
                    email: 'admin@rawwealthy.com',
                    password: 'Admin123!',
                    token: generateToken(admin._id)
                },
                user: {
                    email: 'john@example.com',
                    password: 'Password123!',
                    token: generateToken(user._id)
                },
                plans: plans.length
            }
        });
    } catch (error) {
        console.error('Seed error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to seed database'
        });
    }
});

// ==================== ERROR HANDLING ====================

// 404 handler
app.use((req, res) => {
    res.status(404).json({
        success: false,
        message: `Route ${req.originalUrl} not found`
    });
});

// Global error handler
app.use((err, req, res, next) => {
    console.error('Error:', err.stack);

    if (err.name === 'ValidationError') {
        return res.status(400).json({
            success: false,
            message: 'Validation Error',
            errors: Object.values(err.errors).map(e => e.message)
        });
    }

    if (err.name === 'UnauthorizedError') {
        return res.status(401).json({
            success: false,
            message: 'Unauthorized'
        });
    }

    if (err.code === 11000) {
        const field = Object.keys(err.keyPattern)[0];
        return res.status(400).json({
            success: false,
            message: `${field} already exists`
        });
    }

    res.status(err.status || 500).json({
        success: false,
        message: err.message || 'Internal server error'
    });
});

// ==================== START SERVER ====================

app.listen(PORT, '0.0.0.0', () => {
    console.log(`
    🚀 Raw Wealthy Backend Server Started!
    
    📍 Port: ${PORT}
    🌐 Environment: ${process.env.NODE_ENV || 'development'}
    🗄️ Database: ${MONGODB_URI}
    📁 Uploads: ${uploadsDir}
    
    ✅ Health Check: http://localhost:${PORT}/api/health
    ✅ Debug Routes: http://localhost:${PORT}/api/debug/paths
    ✅ Seed Database: http://localhost:${PORT}/api/seed
    
    🔒 JWT Secret: ${process.env.JWT_SECRET ? 'Set' : 'Using default'}
    ✉️ Email Service: ${process.env.EMAIL_USER ? 'Configured' : 'Not configured'}
    `);
});

module.exports = app;
