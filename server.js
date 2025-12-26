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
const multer = require('multer');

const app = express();
const PORT = process.env.PORT || 10000;

console.log('🚀 Starting Raw Wealthy Backend...');
console.log('📁 Current directory:', __dirname);
console.log('⚙️ Environment:', process.env.NODE_ENV || 'development');

// ============================================
// 1. CREATE UPLOADS DIRECTORY
// ============================================
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
    fs.mkdirSync(uploadsDir, { recursive: true });
    console.log('✅ Created uploads directory');
}

// ============================================
// 2. MIDDLEWARE
// ============================================
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(helmet());
app.use(cors({
    origin: '*',
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS']
}));
app.use(compression());
app.use(morgan('dev'));

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: 'Too many requests from this IP, please try again later.'
});
app.use('/api/', limiter);

// ============================================
// 3. MOCK DATA
// ============================================
const mockPlans = [
    {
        _id: '1',
        name: 'Cocoa Beans',
        description: 'Invest in premium cocoa beans with stable returns',
        min_amount: 3500,
        daily_interest: 2.5,
        total_interest: 75,
        duration: 30,
        risk_level: 'low',
        is_popular: true,
        is_active: true
    },
    {
        _id: '2',
        name: 'Gold',
        description: 'Precious metal investment with high liquidity',
        min_amount: 50000,
        daily_interest: 3.2,
        total_interest: 96,
        duration: 30,
        risk_level: 'medium',
        is_popular: true,
        is_active: true
    },
    {
        _id: '3',
        name: 'Crude Oil',
        description: 'Energy sector investment with premium returns',
        min_amount: 100000,
        daily_interest: 4.1,
        total_interest: 123,
        duration: 30,
        risk_level: 'high',
        is_popular: false,
        is_active: true
    }
];

// ============================================
// 4. ALL REQUIRED ROUTES
// ============================================

// HEALTH CHECK
app.get('/api/health', (req, res) => {
    res.status(200).json({
        success: true,
        message: 'Raw Wealthy Backend is running',
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        database: 'connected',
        version: '1.0.0'
    });
});

// REGISTRATION
app.post('/api/auth/register', (req, res) => {
    const { full_name, email, phone, password } = req.body;
    
    if (!full_name || !email || !phone || !password) {
        return res.status(400).json({
            success: false,
            message: 'All fields are required'
        });
    }
    
    const mockUser = {
        _id: 'mock_' + Date.now(),
        full_name,
        email,
        phone,
        balance: 0,
        referral_code: 'MOCK' + Math.random().toString(36).substr(2, 6).toUpperCase(),
        kyc_status: 'not_submitted',
        role: 'user',
        created_at: new Date().toISOString()
    };
    
    const mockToken = 'mock_jwt_token_' + Date.now();
    
    res.status(201).json({
        success: true,
        message: 'Registration successful',
        data: {
            token: mockToken,
            user: mockUser
        }
    });
});

// LOGIN (MISSING ROUTE)
app.post('/api/auth/login', (req, res) => {
    const { email, password } = req.body;
    
    if (!email || !password) {
        return res.status(400).json({
            success: false,
            message: 'Email and password are required'
        });
    }
    
    const mockUser = {
        _id: 'user_123',
        full_name: 'Demo User',
        email: email,
        phone: '+2348123456789',
        balance: 50000,
        referral_code: 'DEMO123',
        kyc_status: 'verified',
        role: 'user',
        total_earnings: 15000,
        total_invested: 20000,
        referral_earnings: 5000,
        created_at: new Date().toISOString()
    };
    
    const mockToken = 'mock_jwt_token_' + Date.now();
    
    res.json({
        success: true,
        message: 'Login successful',
        data: {
            token: mockToken,
            user: mockUser
        }
    });
});

// GET USER PROFILE
app.get('/api/profile', (req, res) => {
    const token = req.headers.authorization;
    
    if (!token) {
        return res.status(401).json({
            success: false,
            message: 'No authorization token'
        });
    }
    
    const mockUser = {
        _id: 'user_123',
        full_name: 'Demo User',
        email: 'demo@rawwealthy.com',
        phone: '+2348123456789',
        balance: 50000,
        total_earnings: 15000,
        total_invested: 20000,
        referral_earnings: 5000,
        referral_code: 'DEMO123',
        kyc_status: 'verified',
        role: 'user',
        bank_details: {
            bank_name: 'Demo Bank',
            account_name: 'Demo User',
            account_number: '0123456789'
        },
        created_at: new Date().toISOString()
    };
    
    res.json({
        success: true,
        data: { user: mockUser }
    });
});

// UPDATE PROFILE
app.put('/api/profile', (req, res) => {
    res.json({
        success: true,
        message: 'Profile updated successfully'
    });
});

// UPDATE BANK DETAILS
app.put('/api/profile/bank', (req, res) => {
    res.json({
        success: true,
        message: 'Bank details updated successfully'
    });
});

// GET INVESTMENT PLANS
app.get('/api/plans', (req, res) => {
    res.json({
        success: true,
        count: mockPlans.length,
        data: { plans: mockPlans }
    });
});

// GET SPECIFIC PLAN
app.get('/api/plans/:id', (req, res) => {
    const plan = mockPlans.find(p => p._id === req.params.id);
    
    if (!plan) {
        return res.status(404).json({
            success: false,
            message: 'Plan not found'
        });
    }
    
    res.json({
        success: true,
        data: { plan }
    });
});

// GET USER INVESTMENTS
app.get('/api/investments', (req, res) => {
    const mockInvestments = [
        {
            _id: 'inv_1',
            plan: mockPlans[0],
            amount: 3500,
            status: 'active',
            start_date: new Date().toISOString(),
            end_date: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString(),
            total_earned: 875
        }
    ];
    
    res.json({
        success: true,
        data: { investments: mockInvestments }
    });
});

// CREATE INVESTMENT
app.post('/api/investments', (req, res) => {
    const { plan_id, amount } = req.body;
    
    if (!plan_id || !amount) {
        return res.status(400).json({
            success: false,
            message: 'Plan ID and amount are required'
        });
    }
    
    const plan = mockPlans.find(p => p._id === plan_id);
    
    if (!plan) {
        return res.status(404).json({
            success: false,
            message: 'Investment plan not found'
        });
    }
    
    if (amount < plan.min_amount) {
        return res.status(400).json({
            success: false,
            message: `Minimum investment for ${plan.name} is ₦${plan.min_amount}`
        });
    }
    
    const mockInvestment = {
        _id: 'inv_' + Date.now(),
        plan: plan,
        amount: amount,
        status: 'pending',
        created_at: new Date().toISOString()
    };
    
    res.status(201).json({
        success: true,
        message: 'Investment request submitted',
        data: { investment: mockInvestment }
    });
});

// GET TRANSACTIONS
app.get('/api/transactions', (req, res) => {
    const mockTransactions = [
        {
            _id: 'txn_1',
            type: 'deposit',
            amount: 50000,
            description: 'Bank Transfer Deposit',
            status: 'completed',
            created_at: new Date().toISOString()
        }
    ];
    
    res.json({
        success: true,
        data: { transactions: mockTransactions }
    });
});

// GET DASHBOARD STATS
app.get('/api/dashboard/stats', (req, res) => {
    res.json({
        success: true,
        data: {
            user: {
                balance: 50000,
                total_earnings: 15000,
                referral_earnings: 5000
            },
            dashboard_stats: {
                total_invested: 20000,
                total_earned: 15000,
                active_investments: 1,
                active_investment_value: 3500,
                daily_earnings: 87.5
            },
            active_investments: [
                {
                    _id: 'inv_1',
                    plan: { name: 'Cocoa Beans' },
                    amount: 3500,
                    remaining_days: 25,
                    total_earned: 875
                }
            ],
            recent_transactions: [
                {
                    _id: 'txn_1',
                    type: 'deposit',
                    amount: 50000,
                    description: 'Bank Transfer',
                    created_at: new Date().toISOString()
                }
            ]
        }
    });
});

// CREATE DEPOSIT
app.post('/api/deposits', (req, res) => {
    const { amount, payment_method } = req.body;
    
    if (!amount || !payment_method) {
        return res.status(400).json({
            success: false,
            message: 'Amount and payment method are required'
        });
    }
    
    if (amount < 500) {
        return res.status(400).json({
            success: false,
            message: 'Minimum deposit is ₦500'
        });
    }
    
    const mockDeposit = {
        _id: 'dep_' + Date.now(),
        amount: amount,
        payment_method: payment_method,
        status: 'pending',
        created_at: new Date().toISOString()
    };
    
    res.status(201).json({
        success: true,
        message: 'Deposit request submitted',
        data: { deposit: mockDeposit }
    });
});

// CREATE WITHDRAWAL
app.post('/api/withdrawals', (req, res) => {
    const { amount, payment_method } = req.body;
    
    if (!amount || !payment_method) {
        return res.status(400).json({
            success: false,
            message: 'Amount and payment method are required'
        });
    }
    
    if (amount < 1000) {
        return res.status(400).json({
            success: false,
            message: 'Minimum withdrawal is ₦1000'
        });
    }
    
    const platformFee = amount * 0.05;
    const netAmount = amount - platformFee;
    
    const mockWithdrawal = {
        _id: 'wth_' + Date.now(),
        amount: amount,
        platform_fee: platformFee,
        net_amount: netAmount,
        payment_method: payment_method,
        status: 'pending',
        created_at: new Date().toISOString()
    };
    
    res.status(201).json({
        success: true,
        message: 'Withdrawal request submitted',
        data: { withdrawal: mockWithdrawal }
    });
});

// KYC SUBMISSION
app.post('/api/kyc', (req, res) => {
    res.status(201).json({
        success: true,
        message: 'KYC submitted successfully',
        data: { status: 'pending' }
    });
});

// GET KYC STATUS
app.get('/api/kyc/status', (req, res) => {
    res.json({
        success: true,
        data: { status: 'verified' }
    });
});

// SUPPORT TICKET
app.post('/api/support', (req, res) => {
    res.status(201).json({
        success: true,
        message: 'Support ticket submitted'
    });
});

// REFERRAL STATS
app.get('/api/referrals/stats', (req, res) => {
    res.json({
        success: true,
        data: {
            stats: {
                total_referrals: 5,
                active_referrals: 3,
                total_earnings: 15000,
                pending_earnings: 5000
            }
        }
    });
});

// REFERRAL LIST
app.get('/api/referrals/list', (req, res) => {
    res.json({
        success: true,
        data: {
            referrals: []
        }
    });
});

// FILE UPLOAD
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, uploadsDir);
    },
    filename: function (req, file, cb) {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
    }
});
const upload = multer({ 
    storage: storage,
    limits: { fileSize: 5 * 1024 * 1024 }
});

app.post('/api/upload', upload.single('file'), (req, res) => {
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
});

// LIST ALL ENDPOINTS
app.get('/api/endpoints', (req, res) => {
    res.json({
        success: true,
        endpoints: [
            { method: 'GET', path: '/api/health', description: 'Health check' },
            { method: 'POST', path: '/api/auth/register', description: 'Register user' },
            { method: 'POST', path: '/api/auth/login', description: 'Login user' },
            { method: 'GET', path: '/api/profile', description: 'Get user profile' },
            { method: 'PUT', path: '/api/profile', description: 'Update profile' },
            { method: 'PUT', path: '/api/profile/bank', description: 'Update bank details' },
            { method: 'GET', path: '/api/plans', description: 'Get investment plans' },
            { method: 'POST', path: '/api/investments', description: 'Create investment' },
            { method: 'GET', path: '/api/investments', description: 'Get user investments' },
            { method: 'GET', path: '/api/transactions', description: 'Get transactions' },
            { method: 'GET', path: '/api/dashboard/stats', description: 'Dashboard statistics' },
            { method: 'POST', path: '/api/deposits', description: 'Create deposit' },
            { method: 'POST', path: '/api/withdrawals', description: 'Create withdrawal' },
            { method: 'POST', path: '/api/kyc', description: 'Submit KYC' },
            { method: 'GET', path: '/api/kyc/status', description: 'Get KYC status' },
            { method: 'POST', path: '/api/support', description: 'Submit support ticket' },
            { method: 'GET', path: '/api/referrals/stats', description: 'Get referral stats' },
            { method: 'GET', path: '/api/referrals/list', description: 'Get referral list' },
            { method: 'POST', path: '/api/upload', description: 'File upload' }
        ]
    });
});

// ROOT ENDPOINT
app.get('/', (req, res) => {
    res.json({
        message: 'Welcome to Raw Wealthy Investment Platform API',
        version: '1.0.0',
        status: 'operational',
        documentation: 'Visit /api/endpoints for available routes'
    });
});

// 404 HANDLER
app.use((req, res) => {
    res.status(404).json({
        success: false,
        message: `Route ${req.originalUrl} not found`,
        suggestion: 'Visit /api/endpoints for available routes'
    });
});

// ERROR HANDLER
app.use((err, req, res, next) => {
    console.error('Server error:', err.stack);
    res.status(500).json({
        success: false,
        message: 'Something went wrong!',
        error: process.env.NODE_ENV === 'development' ? err.message : 'Internal server error'
    });
});

// ============================================
// 5. START SERVER
// ============================================
app.listen(PORT, '0.0.0.0', () => {
    console.log(`✅ Server running on port ${PORT}`);
    console.log(`✅ Health check: http://0.0.0.0:${PORT}/api/health`);
    console.log(`✅ Available at: https://real-wealthy-1.onrender.com`);
    console.log(`✅ Login endpoint: POST https://real-wealthy-1.onrender.com/api/auth/login`);
});
