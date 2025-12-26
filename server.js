
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
const compression = require('compression');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const path = require('path');
const multer = require('multer');

const app = express();
const PORT = process.env.PORT || 10000;
const JWT_SECRET = process.env.JWT_SECRET || 'raw-wealthy-super-secret-key-2024';
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/raw-wealthy';

// ==================== SECURITY & MIDDLEWARE ====================
app.use(helmet({
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false
}));

app.use(cors({
    origin: ['http://localhost:3000', 'https://rawwealthy.com', 'https://real-wealthy-1.onrender.com'],
    credentials: true
}));

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 1000,
    message: 'Too many requests from this IP'
});
app.use('/api/', limiter);

// Body parsing
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Compression
app.use(compression());

// Logging
if (process.env.NODE_ENV === 'production') {
    app.use(morgan('combined'));
} else {
    app.use(morgan('dev'));
}

// Static files
app.use('/uploads', express.static('uploads'));

// Create uploads directory if it doesn't exist
const fs = require('fs');
if (!fs.existsSync('uploads')) {
    fs.mkdirSync('uploads');
}

// ==================== FILE UPLOAD CONFIGURATION ====================
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'uploads/');
    },
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
    }
});

const upload = multer({
    storage: storage,
    limits: { fileSize: 10 * 1024 * 1024 }, // 10MB
    fileFilter: (req, file, cb) => {
        const allowedTypes = /jpeg|jpg|png|pdf/;
        const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
        const mimetype = allowedTypes.test(file.mimetype);
        
        if (mimetype && extname) {
            return cb(null, true);
        } else {
            cb(new Error('Only images (JPEG, PNG) and PDFs are allowed'));
        }
    }
});

// ==================== DATABASE MODELS ====================
// User Schema
const userSchema = new mongoose.Schema({
    full_name: {
        type: String,
        required: [true, 'Full name is required'],
        trim: true
    },
    email: {
        type: String,
        required: [true, 'Email is required'],
        unique: true,
        lowercase: true,
        trim: true
    },
    phone: {
        type: String,
        required: [true, 'Phone number is required'],
        unique: true
    },
    password: {
        type: String,
        required: [true, 'Password is required'],
        minlength: [6, 'Password must be at least 6 characters'],
        select: false
    },
    role: {
        type: String,
        enum: ['user', 'admin', 'super_admin'],
        default: 'user'
    },
    balance: {
        type: Number,
        default: 0
    },
    total_earnings: {
        type: Number,
        default: 0
    },
    total_invested: {
        type: Number,
        default: 0
    },
    total_withdrawn: {
        type: Number,
        default: 0
    },
    referral_earnings: {
        type: Number,
        default: 0
    },
    referral_code: {
        type: String,
        unique: true,
        uppercase: true
    },
    referred_by: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User'
    },
    referral_count: {
        type: Number,
        default: 0
    },
    risk_tolerance: {
        type: String,
        enum: ['low', 'medium', 'high'],
        default: 'medium'
    },
    kyc_status: {
        type: String,
        enum: ['pending', 'verified', 'rejected', 'not_submitted'],
        default: 'not_submitted'
    },
    bank_details: {
        bank_name: String,
        account_name: String,
        account_number: String,
        verified: {
            type: Boolean,
            default: false
        }
    },
    two_factor_enabled: {
        type: Boolean,
        default: false
    },
    two_factor_secret: String,
    is_active: {
        type: Boolean,
        default: true
    },
    is_email_verified: {
        type: Boolean,
        default: false
    },
    is_phone_verified: {
        type: Boolean,
        default: false
    },
    password_reset_token: String,
    password_reset_expires: Date,
    email_verification_token: String,
    email_verification_expires: Date,
    last_login: Date,
    last_login_ip: String,
    created_at: {
        type: Date,
        default: Date.now
    },
    updated_at: {
        type: Date,
        default: Date.now
    }
}, {
    timestamps: { createdAt: 'created_at', updatedAt: 'updated_at' }
});

// Hash password before saving
userSchema.pre('save', async function(next) {
    if (!this.isModified('password')) return next();
    
    try {
        const salt = await bcrypt.genSalt(10);
        this.password = await bcrypt.hash(this.password, salt);
        next();
    } catch (error) {
        next(error);
    }
});

// Generate referral code
userSchema.pre('save', function(next) {
    if (this.isNew && !this.referral_code) {
        const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
        let code = 'RW';
        for (let i = 0; i < 6; i++) {
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

// Create JWT token
userSchema.methods.generateToken = function() {
    return jwt.sign(
        { id: this._id, email: this.email, role: this.role },
        JWT_SECRET,
        { expiresIn: '30d' }
    );
};

const User = mongoose.model('User', userSchema);

// Investment Plan Schema
const investmentPlanSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true,
        unique: true
    },
    description: {
        type: String,
        required: true
    },
    min_amount: {
        type: Number,
        required: true,
        min: 3500
    },
    max_amount: Number,
    daily_interest: {
        type: Number,
        required: true,
        min: 0,
        max: 100
    },
    total_interest: {
        type: Number,
        required: true,
        min: 0
    },
    duration: {
        type: Number,
        required: true,
        min: 1
    },
    risk_level: {
        type: String,
        enum: ['low', 'medium', 'high'],
        default: 'medium'
    },
    category: {
        type: String,
        enum: ['cocoa', 'gold', 'oil', 'agriculture', 'mining', 'energy'],
        required: true
    },
    is_active: {
        type: Boolean,
        default: true
    },
    is_popular: {
        type: Boolean,
        default: false
    },
    total_investors: {
        type: Number,
        default: 0
    },
    total_invested: {
        type: Number,
        default: 0
    },
    created_at: {
        type: Date,
        default: Date.now
    }
});

const InvestmentPlan = mongoose.model('InvestmentPlan', investmentPlanSchema);

// Investment Schema
const investmentSchema = new mongoose.Schema({
    user: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    plan: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'InvestmentPlan',
        required: true
    },
    amount: {
        type: Number,
        required: true,
        min: 3500
    },
    daily_interest: {
        type: Number,
        required: true
    },
    total_interest: {
        type: Number,
        required: true
    },
    daily_earnings: {
        type: Number,
        default: 0
    },
    total_earned: {
        type: Number,
        default: 0
    },
    expected_total: {
        type: Number,
        required: true
    },
    duration: {
        type: Number,
        required: true
    },
    start_date: {
        type: Date,
        default: Date.now
    },
    end_date: {
        type: Date,
        required: true
    },
    status: {
        type: String,
        enum: ['pending', 'active', 'completed', 'cancelled', 'suspended'],
        default: 'pending'
    },
    auto_renew: {
        type: Boolean,
        default: false
    },
    payment_proof_url: String,
    payment_proof_verified: {
        type: Boolean,
        default: false
    },
    last_payout: Date,
    payout_count: {
        type: Number,
        default: 0
    },
    approved_by: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User'
    },
    approved_at: Date,
    created_at: {
        type: Date,
        default: Date.now
    }
});

const Investment = mongoose.model('Investment', investmentSchema);

// Transaction Schema
const transactionSchema = new mongoose.Schema({
    user: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    type: {
        type: String,
        enum: ['deposit', 'withdrawal', 'investment', 'earnings', 'referral', 'bonus', 'refund'],
        required: true
    },
    amount: {
        type: Number,
        required: true
    },
    description: {
        type: String,
        required: true
    },
    reference: {
        type: String,
        required: true,
        unique: true
    },
    status: {
        type: String,
        enum: ['pending', 'completed', 'failed', 'cancelled'],
        default: 'pending'
    },
    balance_before: Number,
    balance_after: Number,
    metadata: {
        investment_id: mongoose.Schema.Types.ObjectId,
        deposit_id: mongoose.Schema.Types.ObjectId,
        withdrawal_id: mongoose.Schema.Types.ObjectId,
        plan_name: String,
        payment_method: String
    },
    created_at: {
        type: Date,
        default: Date.now
    }
});

const Transaction = mongoose.model('Transaction', transactionSchema);

// Deposit Schema
const depositSchema = new mongoose.Schema({
    user: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    amount: {
        type: Number,
        required: true,
        min: 500
    },
    payment_method: {
        type: String,
        enum: ['bank_transfer', 'crypto', 'paypal', 'card'],
        required: true
    },
    payment_proof_url: {
        type: String,
        required: true
    },
    status: {
        type: String,
        enum: ['pending', 'completed', 'rejected', 'cancelled'],
        default: 'pending'
    },
    transaction: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Transaction'
    },
    processed_by: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User'
    },
    processed_at: Date,
    remarks: String,
    created_at: {
        type: Date,
        default: Date.now
    }
});

const Deposit = mongoose.model('Deposit', depositSchema);

// Withdrawal Schema
const withdrawalSchema = new mongoose.Schema({
    user: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    amount: {
        type: Number,
        required: true,
        min: 1000
    },
    platform_fee: {
        type: Number,
        default: 0
    },
    net_amount: {
        type: Number,
        required: true
    },
    payment_method: {
        type: String,
        enum: ['bank_transfer', 'crypto', 'paypal'],
        required: true
    },
    status: {
        type: String,
        enum: ['pending', 'completed', 'rejected', 'cancelled'],
        default: 'pending'
    },
    transaction: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Transaction'
    },
    transaction_id: String,
    processed_by: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User'
    },
    processed_at: Date,
    remarks: String,
    created_at: {
        type: Date,
        default: Date.now
    }
});

const Withdrawal = mongoose.model('Withdrawal', withdrawalSchema);

// ==================== AUTHENTICATION MIDDLEWARE ====================
const protect = async (req, res, next) => {
    try {
        let token;

        if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
            token = req.headers.authorization.split(' ')[1];
        }

        if (!token) {
            return res.status(401).json({
                success: false,
                message: 'Not authorized to access this route'
            });
        }

        const decoded = jwt.verify(token, JWT_SECRET);
        const user = await User.findById(decoded.id).select('-password');

        if (!user) {
            return res.status(401).json({
                success: false,
                message: 'User not found'
            });
        }

        if (!user.is_active) {
            return res.status(403).json({
                success: false,
                message: 'Account is deactivated'
            });
        }

        req.user = user;
        next();
    } catch (error) {
        if (error.name === 'JsonWebTokenError') {
            return res.status(401).json({
                success: false,
                message: 'Invalid token'
            });
        }

        if (error.name === 'TokenExpiredError') {
            return res.status(401).json({
                success: false,
                message: 'Token expired'
            });
        }

        res.status(500).json({
            success: false,
            message: 'Authentication error'
        });
    }
};

const admin = (req, res, next) => {
    if (req.user.role !== 'admin' && req.user.role !== 'super_admin') {
        return res.status(403).json({
            success: false,
            message: 'Not authorized as admin'
        });
    }
    next();
};

// ==================== DATABASE CONNECTION ====================
const connectDB = async () => {
    try {
        await mongoose.connect(MONGODB_URI, {
            useNewUrlParser: true,
            useUnifiedTopology: true,
        });
        
        console.log('✅ MongoDB connected successfully');
        
        // Seed initial data if database is empty
        await seedInitialData();
        
    } catch (error) {
        console.error('❌ MongoDB connection error:', error);
        process.exit(1);
    }
};

// ==================== SEED INITIAL DATA ====================
const seedInitialData = async () => {
    try {
        // Check if plans exist
        const planCount = await InvestmentPlan.countDocuments();
        if (planCount === 0) {
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
                    is_active: true
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
                    is_active: true
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
                    is_active: true
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
                    is_active: true
                },
                {
                    name: 'Precious Metals',
                    description: 'Diversified precious metals portfolio',
                    min_amount: 75000,
                    daily_interest: 3.5,
                    total_interest: 105,
                    duration: 30,
                    risk_level: 'medium',
                    category: 'mining',
                    is_popular: false,
                    is_active: true
                }
            ];
            
            await InvestmentPlan.insertMany(plans);
            console.log(`✅ ${plans.length} investment plans seeded`);
        }

        // Check if admin user exists
        const adminUser = await User.findOne({ email: 'admin@rawwealthy.com' });
        if (!adminUser) {
            const admin = new User({
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
            await admin.save();
            console.log('✅ Admin user created: admin@rawwealthy.com / Admin123!');
        }

        console.log('✅ Database seeding completed');
    } catch (error) {
        console.error('❌ Database seeding error:', error);
    }
};

// ==================== ROUTE HANDLERS ====================

// Generate unique reference
const generateReference = (prefix) => {
    return `${prefix}-${Date.now()}-${Math.random().toString(36).substr(2, 9).toUpperCase()}`;
};

// Health check
app.get('/api/health', (req, res) => {
    res.status(200).json({
        success: true,
        message: '✅ Raw Wealthy API is running!',
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        environment: process.env.NODE_ENV || 'development',
        database: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected'
    });
});

// Debug endpoint
app.get('/api/debug/paths', (req, res) => {
    const routes = app._router.stack
        .filter(r => r.route)
        .map(r => ({
            path: r.route.path,
            methods: Object.keys(r.route.methods).map(m => m.toUpperCase())
        }));
    
    res.json({
        success: true,
        count: routes.length,
        routes
    });
});

// ==================== AUTH ROUTES ====================

// Register
app.post('/api/auth/register', async (req, res) => {
    try {
        const { full_name, email, phone, password, referral_code, risk_tolerance } = req.body;

        // Validation
        if (!full_name || !email || !phone || !password) {
            return res.status(400).json({
                success: false,
                message: 'Please provide all required fields'
            });
        }

        // Check if user exists
        const existingUser = await User.findOne({ 
            $or: [{ email: email.toLowerCase() }, { phone }] 
        });
        
        if (existingUser) {
            return res.status(400).json({
                success: false,
                message: 'User with this email or phone already exists'
            });
        }

        // Check referral code
        let referredBy = null;
        if (referral_code) {
            const referrer = await User.findOne({ referral_code: referral_code.toUpperCase() });
            if (!referrer) {
                return res.status(400).json({
                    success: false,
                    message: 'Invalid referral code'
                });
            }
            referredBy = referrer._id;
        }

        // Create user
        const user = await User.create({
            full_name,
            email: email.toLowerCase(),
            phone,
            password,
            referred_by: referredBy,
            risk_tolerance: risk_tolerance || 'medium'
        });

        // Handle referral
        if (referredBy) {
            await User.findByIdAndUpdate(referredBy, {
                $inc: { referral_count: 1 }
            });
        }

        // Generate token
        const token = user.generateToken();

        // Return response
        res.status(201).json({
            success: true,
            message: 'Registration successful! Welcome to Raw Wealthy.',
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
        
        if (error.name === 'ValidationError') {
            const messages = Object.values(error.errors).map(val => val.message);
            return res.status(400).json({
                success: false,
                message: messages[0] || 'Validation error'
            });
        }

        res.status(500).json({
            success: false,
            message: 'Registration failed. Please try again.'
        });
    }
});

// Login
app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        // Validate input
        if (!email || !password) {
            return res.status(400).json({
                success: false,
                message: 'Please provide email and password'
            });
        }

        // Find user with password
        const user = await User.findOne({ email: email.toLowerCase() }).select('+password');
        
        if (!user) {
            return res.status(401).json({
                success: false,
                message: 'Invalid credentials'
            });
        }

        // Check password
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

        // Generate token
        const token = user.generateToken();

        // Remove password from response
        user.password = undefined;

        res.status(200).json({
            success: true,
            message: 'Login successful!',
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
            message: 'Login failed. Please try again.'
        });
    }
});

// Get user profile
app.get('/api/profile', protect, async (req, res) => {
    try {
        const user = await User.findById(req.user._id)
            .select('-password -password_reset_token -email_verification_token');

        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        res.status(200).json({
            success: true,
            data: { user }
        });
    } catch (error) {
        console.error('Get profile error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to get profile'
        });
    }
});

// Update profile
app.put('/api/profile', protect, async (req, res) => {
    try {
        const { full_name, phone, country } = req.body;

        const user = await User.findByIdAndUpdate(
            req.user._id,
            { full_name, phone, country },
            { new: true, runValidators: true }
        ).select('-password');

        res.status(200).json({
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

// Update bank details
app.put('/api/profile/bank', protect, async (req, res) => {
    try {
        const { bank_name, account_name, account_number } = req.body;

        const user = await User.findByIdAndUpdate(
            req.user._id,
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

        res.status(200).json({
            success: true,
            message: 'Bank details updated successfully',
            data: { user }
        });
    } catch (error) {
        console.error('Update bank details error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to update bank details'
        });
    }
});

// ==================== INVESTMENT PLANS ROUTES ====================

// Get all investment plans
app.get('/api/plans', async (req, res) => {
    try {
        const plans = await InvestmentPlan.find({ is_active: true })
            .sort({ min_amount: 1 });

        res.status(200).json({
            success: true,
            count: plans.length,
            data: { plans }
        });
    } catch (error) {
        console.error('Get investment plans error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch investment plans'
        });
    }
});

// Get single investment plan
app.get('/api/plans/:id', async (req, res) => {
    try {
        const plan = await InvestmentPlan.findById(req.params.id);

        if (!plan) {
            return res.status(404).json({
                success: false,
                message: 'Investment plan not found'
            });
        }

        res.status(200).json({
            success: true,
            data: { plan }
        });
    } catch (error) {
        console.error('Get investment plan error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch investment plan'
        });
    }
});

// ==================== INVESTMENT ROUTES ====================

// Get user investments
app.get('/api/investments', protect, async (req, res) => {
    try {
        const { status, page = 1, limit = 10 } = req.query;

        // Build query
        const query = { user: req.user._id };
        if (status) {
            query.status = status;
        }

        // Calculate skip
        const skip = (parseInt(page) - 1) * parseInt(limit);

        // Get investments with pagination
        const investments = await Investment.find(query)
            .populate('plan', 'name daily_interest total_interest duration')
            .sort({ created_at: -1 })
            .skip(skip)
            .limit(parseInt(limit));

        // Get total count
        const total = await Investment.countDocuments(query);

        res.status(200).json({
            success: true,
            data: {
                investments,
                pagination: {
                    page: parseInt(page),
                    limit: parseInt(limit),
                    total,
                    pages: Math.ceil(total / parseInt(limit))
                }
            }
        });
    } catch (error) {
        console.error('Get user investments error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch investments'
        });
    }
});

// Create investment
app.post('/api/investments', protect, async (req, res) => {
    try {
        const { plan_id, amount, auto_renew, payment_proof_url } = req.body;

        // Get user
        const user = await User.findById(req.user._id);
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
                message: 'Please complete KYC verification before investing'
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
                message: `Minimum investment for ${plan.name} is ₦${plan.min_amount.toLocaleString()}`
            });
        }

        // Check if user has sufficient balance
        if (user.balance < amount) {
            return res.status(400).json({
                success: false,
                message: 'Insufficient balance'
            });
        }

        // Calculate end date
        const endDate = new Date();
        endDate.setDate(endDate.getDate() + plan.duration);

        // Calculate expected returns
        const dailyEarnings = (amount * plan.daily_interest) / 100;
        const totalEarnings = (amount * plan.total_interest) / 100;
        const expectedTotal = amount + totalEarnings;

        // Create investment
        const investment = await Investment.create({
            user: req.user._id,
            plan: plan_id,
            amount,
            daily_interest: plan.daily_interest,
            total_interest: plan.total_interest,
            daily_earnings: dailyEarnings,
            expected_total: expectedTotal,
            duration: plan.duration,
            end_date: endDate,
            auto_renew: auto_renew || false,
            payment_proof_url: payment_proof_url,
            status: 'pending'
        });

        // Deduct amount from user balance
        user.balance -= amount;
        user.total_invested += amount;
        await user.save();

        // Create transaction record
        await Transaction.create({
            user: req.user._id,
            type: 'investment',
            amount: -amount,
            description: `Investment in ${plan.name} Plan`,
            reference: generateReference('INV'),
            status: 'completed',
            balance_before: user.balance + amount,
            balance_after: user.balance,
            metadata: {
                investment_id: investment._id,
                plan_name: plan.name,
                duration: plan.duration
            }
        });

        // Update plan statistics
        await InvestmentPlan.findByIdAndUpdate(plan_id, {
            $inc: {
                total_investors: 1,
                total_invested: amount
            }
        });

        res.status(201).json({
            success: true,
            message: 'Investment created successfully. Awaiting approval.',
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
        const userId = req.user._id;

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

        res.status(200).json({
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
        console.error('Get investment stats error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch investment statistics'
        });
    }
});

// ==================== DASHBOARD ROUTES ====================

// Get dashboard stats
app.get('/api/dashboard/stats', protect, async (req, res) => {
    try {
        const userId = req.user._id;

        // Get user
        const user = await User.findById(userId);

        // Get investment stats
        const investmentStats = await Investment.aggregate([
            { $match: { user: userId } },
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
        .populate('plan', 'name daily_interest')
        .limit(5);

        const stats = investmentStats[0] || {
            total_invested: 0,
            total_earned: 0,
            active_investments: 0,
            active_investment_value: 0
        };

        // Calculate daily earnings from active investments
        let dailyEarnings = 0;
        activeInvestments.forEach(inv => {
            dailyEarnings += (inv.amount * inv.daily_interest) / 100;
        });

        // Generate sample earnings data for chart
        const earningsData = [];
        for (let i = 6; i >= 0; i--) {
            const date = new Date();
            date.setDate(date.getDate() - i);
            earningsData.push({
                date: date.toISOString().split('T')[0],
                earnings: Math.floor(dailyEarnings * (0.8 + Math.random() * 0.4))
            });
        }

        res.status(200).json({
            success: true,
            data: {
                user: {
                    balance: user.balance,
                    total_earnings: user.total_earnings,
                    referral_earnings: user.referral_earnings
                },
                dashboard_stats: {
                    ...stats,
                    daily_earnings: dailyEarnings
                },
                daily_earnings: earningsData,
                active_investments,
                recent_transactions: transactions
            }
        });
    } catch (error) {
        console.error('Get dashboard stats error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to get dashboard stats'
        });
    }
});

// ==================== TRANSACTION ROUTES ====================

// Get user transactions
app.get('/api/transactions', protect, async (req, res) => {
    try {
        const { type, page = 1, limit = 10 } = req.query;

        // Build query
        const query = { user: req.user._id };
        if (type) {
            query.type = type;
        }

        // Calculate skip
        const skip = (parseInt(page) - 1) * parseInt(limit);

        // Get transactions with pagination
        const transactions = await Transaction.find(query)
            .sort({ created_at: -1 })
            .skip(skip)
            .limit(parseInt(limit));

        // Get total count
        const total = await Transaction.countDocuments(query);

        res.status(200).json({
            success: true,
            data: {
                transactions,
                pagination: {
                    page: parseInt(page),
                    limit: parseInt(limit),
                    total,
                    pages: Math.ceil(total / parseInt(limit))
                }
            }
        });
    } catch (error) {
        console.error('Get transactions error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch transactions'
        });
    }
});

// ==================== DEPOSIT ROUTES ====================

// Get user deposits
app.get('/api/deposits', protect, async (req, res) => {
    try {
        const { status, page = 1, limit = 10 } = req.query;

        // Build query
        const query = { user: req.user._id };
        if (status) {
            query.status = status;
        }

        // Calculate skip
        const skip = (parseInt(page) - 1) * parseInt(limit);

        // Get deposits with pagination
        const deposits = await Deposit.find(query)
            .sort({ created_at: -1 })
            .skip(skip)
            .limit(parseInt(limit));

        // Get total count
        const total = await Deposit.countDocuments(query);

        res.status(200).json({
            success: true,
            data: {
                deposits,
                pagination: {
                    page: parseInt(page),
                    limit: parseInt(limit),
                    total,
                    pages: Math.ceil(total / parseInt(limit))
                }
            }
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
app.post('/api/deposits', protect, async (req, res) => {
    try {
        const { amount, payment_method, payment_proof_url } = req.body;

        // Validate amount
        if (amount < 500) {
            return res.status(400).json({
                success: false,
                message: 'Minimum deposit is ₦500'
            });
        }

        // Create deposit
        const deposit = await Deposit.create({
            user: req.user._id,
            amount,
            payment_method,
            payment_proof_url,
            status: 'pending'
        });

        // Create transaction
        const transaction = await Transaction.create({
            user: req.user._id,
            type: 'deposit',
            amount: amount,
            description: `Deposit via ${payment_method}`,
            reference: generateReference('DEP'),
            status: 'pending',
            metadata: {
                deposit_id: deposit._id,
                payment_method: payment_method
            }
        });

        // Link transaction to deposit
        deposit.transaction = transaction._id;
        await deposit.save();

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

// ==================== WITHDRAWAL ROUTES ====================

// Get user withdrawals
app.get('/api/withdrawals', protect, async (req, res) => {
    try {
        const { status, page = 1, limit = 10 } = req.query;

        // Build query
        const query = { user: req.user._id };
        if (status) {
            query.status = status;
        }

        // Calculate skip
        const skip = (parseInt(page) - 1) * parseInt(limit);

        // Get withdrawals with pagination
        const withdrawals = await Withdrawal.find(query)
            .sort({ created_at: -1 })
            .skip(skip)
            .limit(parseInt(limit));

        // Get total count
        const total = await Withdrawal.countDocuments(query);

        res.status(200).json({
            success: true,
            data: {
                withdrawals,
                pagination: {
                    page: parseInt(page),
                    limit: parseInt(limit),
                    total,
                    pages: Math.ceil(total / parseInt(limit))
                }
            }
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

        // Validate amount
        if (amount < 1000) {
            return res.status(400).json({
                success: false,
                message: 'Minimum withdrawal is ₦1000'
            });
        }

        // Get user
        const user = await User.findById(req.user._id);
        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        // Check if user has sufficient balance
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
            user: req.user._id,
            amount,
            platform_fee: platformFee,
            net_amount: netAmount,
            payment_method,
            status: 'pending'
        });

        // Create transaction
        const transaction = await Transaction.create({
            user: req.user._id,
            type: 'withdrawal',
            amount: -amount,
            description: `Withdrawal via ${payment_method}`,
            reference: generateReference('WTH'),
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

        // Link transaction to withdrawal
        withdrawal.transaction = transaction._id;
        await withdrawal.save();

        // Deduct amount from user balance
        user.balance -= amount;
        user.total_withdrawn += amount;
        await user.save();

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

// ==================== FILE UPLOAD ROUTE ====================

app.post('/api/upload', protect, upload.single('file'), (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({
                success: false,
                message: 'No file uploaded'
            });
        }

        res.status(200).json({
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
        console.error('File upload error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to upload file'
        });
    }
});

// ==================== ADMIN ROUTES ====================

// Get admin dashboard stats
app.get('/api/admin/dashboard', protect, admin, async (req, res) => {
    try {
        // Get counts
        const totalUsers = await User.countDocuments();
        const totalInvestments = await Investment.countDocuments();
        const activeInvestments = await Investment.countDocuments({ status: 'active' });
        const totalDeposits = await Deposit.countDocuments();
        const totalWithdrawals = await Withdrawal.countDocuments();
        
        // Get sums
        const totalInvestedResult = await Investment.aggregate([
            { $group: { _id: null, total: { $sum: '$amount' } } }
        ]);
        const totalInvested = totalInvestedResult[0]?.total || 0;
        
        const totalWithdrawnResult = await Withdrawal.aggregate([
            { $group: { _id: null, total: { $sum: '$amount' } } }
        ]);
        const totalWithdrawn = totalWithdrawnResult[0]?.total || 0;

        res.status(200).json({
            success: true,
            data: {
                total_users: totalUsers,
                total_invested: totalInvested,
                total_withdrawn: totalWithdrawn,
                total_deposits: totalDeposits,
                total_withdrawals: totalWithdrawals,
                active_investments: activeInvestments,
                total_investments: totalInvestments,
                platform_earnings: totalWithdrawn * 0.05, // 5% platform fee
                pending_requests: 0 // You can implement this
            }
        });
    } catch (error) {
        console.error('Get admin dashboard error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to get admin dashboard stats'
        });
    }
});

// Get all users (admin)
app.get('/api/admin/users', protect, admin, async (req, res) => {
    try {
        const { page = 1, limit = 20 } = req.query;
        const skip = (parseInt(page) - 1) * parseInt(limit);

        const users = await User.find()
            .select('-password')
            .sort({ created_at: -1 })
            .skip(skip)
            .limit(parseInt(limit));

        const total = await User.countDocuments();

        res.status(200).json({
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
        console.error('Get users error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to get users'
        });
    }
});

// Get pending investments (admin)
app.get('/api/admin/pending-investments', protect, admin, async (req, res) => {
    try {
        const investments = await Investment.find({ status: 'pending' })
            .populate('user', 'full_name email phone')
            .populate('plan', 'name')
            .sort({ created_at: -1 });

        res.status(200).json({
            success: true,
            data: { investments }
        });
    } catch (error) {
        console.error('Get pending investments error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to get pending investments'
        });
    }
});

// Approve investment (admin)
app.post('/api/admin/investments/:id/approve', protect, admin, async (req, res) => {
    try {
        const investment = await Investment.findById(req.params.id)
            .populate('plan');

        if (!investment) {
            return res.status(404).json({
                success: false,
                message: 'Investment not found'
            });
        }

        investment.status = 'active';
        investment.approved_by = req.user._id;
        investment.approved_at = new Date();
        investment.payment_proof_verified = true;
        await investment.save();

        res.status(200).json({
            success: true,
            message: 'Investment approved successfully'
        });
    } catch (error) {
        console.error('Approve investment error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to approve investment'
        });
    }
});

// Get pending deposits (admin)
app.get('/api/admin/pending-deposits', protect, admin, async (req, res) => {
    try {
        const deposits = await Deposit.find({ status: 'pending' })
            .populate('user', 'full_name email phone')
            .sort({ created_at: -1 });

        res.status(200).json({
            success: true,
            data: { deposits }
        });
    } catch (error) {
        console.error('Get pending deposits error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to get pending deposits'
        });
    }
});

// Approve deposit (admin)
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

        // Update deposit
        deposit.status = 'completed';
        deposit.processed_by = req.user._id;
        deposit.processed_at = new Date();
        await deposit.save();

        // Update user balance
        const user = await User.findById(deposit.user._id);
        user.balance += deposit.amount;
        await user.save();

        // Update transaction
        await Transaction.findByIdAndUpdate(deposit.transaction, {
            status: 'completed',
            balance_before: user.balance - deposit.amount,
            balance_after: user.balance
        });

        res.status(200).json({
            success: true,
            message: 'Deposit approved successfully'
        });
    } catch (error) {
        console.error('Approve deposit error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to approve deposit'
        });
    }
});

// Get pending withdrawals (admin)
app.get('/api/admin/pending-withdrawals', protect, admin, async (req, res) => {
    try {
        const withdrawals = await Withdrawal.find({ status: 'pending' })
            .populate('user', 'full_name email phone')
            .sort({ created_at: -1 });

        res.status(200).json({
            success: true,
            data: { withdrawals }
        });
    } catch (error) {
        console.error('Get pending withdrawals error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to get pending withdrawals'
        });
    }
});

// Approve withdrawal (admin)
app.post('/api/admin/withdrawals/:id/approve', protect, admin, async (req, res) => {
    try {
        const withdrawal = await Withdrawal.findById(req.params.id);

        if (!withdrawal) {
            return res.status(404).json({
                success: false,
                message: 'Withdrawal not found'
            });
        }

        // Update withdrawal
        withdrawal.status = 'completed';
        withdrawal.processed_by = req.user._id;
        withdrawal.processed_at = new Date();
        await withdrawal.save();

        // Update transaction
        await Transaction.findByIdAndUpdate(withdrawal.transaction, {
            status: 'completed'
        });

        res.status(200).json({
            success: true,
            message: 'Withdrawal approved successfully'
        });
    } catch (error) {
        console.error('Approve withdrawal error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to approve withdrawal'
        });
    }
});

// ==================== 404 HANDLER ====================
app.use('/api/*', (req, res) => {
    res.status(404).json({
        success: false,
        message: `Route ${req.originalUrl} not found`
    });
});

// ==================== ERROR HANDLER ====================
app.use((err, req, res, next) => {
    console.error('Server error:', err.stack);

    // Multer errors
    if (err.name === 'MulterError') {
        return res.status(400).json({
            success: false,
            message: err.message
        });
    }

    // Validation errors
    if (err.name === 'ValidationError') {
        const messages = Object.values(err.errors).map(val => val.message);
        return res.status(400).json({
            success: false,
            message: messages[0] || 'Validation error'
        });
    }

    // JWT errors
    if (err.name === 'JsonWebTokenError') {
        return res.status(401).json({
            success: false,
            message: 'Invalid token'
        });
    }

    if (err.name === 'TokenExpiredError') {
        return res.status(401).json({
            success: false,
            message: 'Token expired'
        });
    }

    // Default error
    res.status(err.status || 500).json({
        success: false,
        message: err.message || 'Internal server error',
        ...(process.env.NODE_ENV === 'development' && { stack: err.stack })
    });
});

// ==================== START SERVER ====================
const startServer = async () => {
    try {
        // Connect to database
        await connectDB();
        
        // Start server
        app.listen(PORT, '0.0.0.0', () => {
            console.log('🚀 Raw Wealthy Backend Started Successfully!');
            console.log(`📁 Environment: ${process.env.NODE_ENV || 'development'}`);
            console.log(`🌐 Server running on port ${PORT}`);
            console.log(`✅ Health check: http://localhost:${PORT}/api/health`);
            console.log(`✅ Available at: https://real-wealthy-1.onrender.com`);
            console.log(`✅ Admin login: admin@rawwealthy.com / Admin123!`);
            console.log(`📊 Database: ${mongoose.connection.readyState === 1 ? '✅ Connected' : '❌ Disconnected'}`);
        });
    } catch (error) {
        console.error('❌ Failed to start server:', error);
        process.exit(1);
    }
};

startServer();

module.exports = app;
