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

const app = express();
const PORT = process.env.PORT || 10000;

console.log('🚀 Starting Raw Wealthy Backend...');
console.log('📁 Current directory:', __dirname);
console.log('⚙️ Environment:', process.env.NODE_ENV || 'development');

// ============================================
// 1. CREATE UPLOADS DIRECTORY IF NEEDED
// ============================================
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
    fs.mkdirSync(uploadsDir, { recursive: true });
    console.log('✅ Created uploads directory');
}

// ============================================
// 2. MIDDLEWARE SETUP
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
// 3. DATABASE CONNECTION (WITH FALLBACK)
// ============================================
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/raw-wealthy';

if (MONGODB_URI && !MONGODB_URI.includes('your-')) {
    mongoose.connect(MONGODB_URI, {
        useNewUrlParser: true,
        useUnifiedTopology: true,
    })
    .then(() => console.log('✅ MongoDB connected'))
    .catch(err => console.log('❌ MongoDB connection failed:', err.message));
} else {
    console.log('⚠️ No valid MongoDB URI found, running in mock mode');
}

// ============================================
// 4. MOCK DATA FOR TESTING
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
// 5. ESSENTIAL ROUTES (WORKING WITHOUT MODULES)
// ============================================

// Health check
app.get('/api/health', (req, res) => {
    res.status(200).json({
        success: true,
        message: 'Raw Wealthy Backend is running',
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        database: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
        version: '1.0.0',
        environment: process.env.NODE_ENV || 'development'
    });
});

// Debug info
app.get('/api/debug', (req, res) => {
    res.json({
        server: 'Raw Wealthy Backend',
        status: 'running',
        port: PORT,
        directory: __dirname,
        files: fs.readdirSync(__dirname),
        memory: process.memoryUsage(),
        nodeVersion: process.version
    });
});

// Get investment plans
app.get('/api/plans', (req, res) => {
    res.json({
        success: true,
        count: mockPlans.length,
        data: { plans: mockPlans }
    });
});

// Registration endpoint
app.post('/api/auth/register', (req, res) => {
    const { full_name, email, phone, password } = req.body;
    
    // Basic validation
    if (!full_name || !email || !phone || !password) {
        return res.status(400).json({
            success: false,
            message: 'All fields are required'
        });
    }
    
    // Mock user data
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

// Login endpoint
app.post('/api/auth/login', (req, res) => {
    const { email, password } = req.body;
    
    if (!email || !password) {
        return res.status(400).json({
            success: false,
            message: 'Email and password are required'
        });
    }
    
    // Mock user data
    const mockUser = {
        _id: 'user_123',
        full_name: 'Demo User',
        email: email,
        phone: '+2348123456789',
        balance: 50000,
        referral_code: 'DEMO123',
        kyc_status: 'verified',
        role: 'user',
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

// Profile endpoint
app.get('/api/profile', (req, res) => {
    // Check for authorization header
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

// Investments endpoint
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
        },
        {
            _id: 'inv_2',
            plan: mockPlans[1],
            amount: 50000,
            status: 'active',
            start_date: new Date(Date.now() - 15 * 24 * 60 * 60 * 1000).toISOString(),
            end_date: new Date(Date.now() + 15 * 24 * 60 * 60 * 1000).toISOString(),
            total_earned: 24000
        }
    ];
    
    res.json({
        success: true,
        data: { investments: mockInvestments }
    });
});

// Transactions endpoint
app.get('/api/transactions', (req, res) => {
    const mockTransactions = [
        {
            _id: 'txn_1',
            type: 'deposit',
            amount: 50000,
            description: 'Bank Transfer Deposit',
            status: 'completed',
            created_at: new Date().toISOString()
        },
        {
            _id: 'txn_2',
            type: 'investment',
            amount: -3500,
            description: 'Investment in Cocoa Beans Plan',
            status: 'completed',
            created_at: new Date(Date.now() - 86400000).toISOString()
        },
        {
            _id: 'txn_3',
            type: 'earnings',
            amount: 875,
            description: 'Daily Earnings from Cocoa Investment',
            status: 'completed',
            created_at: new Date().toISOString()
        }
    ];
    
    res.json({
        success: true,
        data: { transactions: mockTransactions }
    });
});

// Create investment endpoint
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

// File upload endpoint
const multer = require('multer');
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
    limits: { fileSize: 5 * 1024 * 1024 } // 5MB limit
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

// Dashboard stats
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
                active_investments: 2,
                active_investment_value: 53500,
                daily_earnings: 750
            },
            daily_earnings: [
                { date: '2024-01-01', earnings: 720 },
                { date: '2024-01-02', earnings: 750 },
                { date: '2024-01-03', earnings: 780 },
                { date: '2024-01-04', earnings: 810 },
                { date: '2024-01-05', earnings: 790 },
                { date: '2024-01-06', earnings: 820 },
                { date: '2024-01-07', earnings: 850 }
            ],
            active_investments: [
                {
                    _id: 'inv_1',
                    plan: { name: 'Cocoa Beans' },
                    amount: 3500,
                    remaining_days: 25,
                    total_earned: 875
                },
                {
                    _id: 'inv_2',
                    plan: { name: 'Gold' },
                    amount: 50000,
                    remaining_days: 15,
                    total_earned: 24000
                }
            ],
            recent_transactions: [
                {
                    _id: 'txn_1',
                    type: 'deposit',
                    amount: 50000,
                    description: 'Bank Transfer',
                    created_at: new Date().toISOString()
                },
                {
                    _id: 'txn_2',
                    type: 'earnings',
                    amount: 875,
                    description: 'Daily Earnings',
                    created_at: new Date(Date.now() - 86400000).toISOString()
                }
            ]
        }
    });
});

// List all available endpoints
app.get('/api/endpoints', (req, res) => {
    res.json({
        success: true,
        endpoints: [
            { method: 'GET', path: '/api/health', description: 'Health check' },
            { method: 'GET', path: '/api/debug', description: 'Debug information' },
            { method: 'GET', path: '/api/plans', description: 'Get investment plans' },
            { method: 'POST', path: '/api/auth/register', description: 'Register user' },
            { method: 'POST', path: '/api/auth/login', description: 'Login user' },
            { method: 'GET', path: '/api/profile', description: 'Get user profile' },
            { method: 'GET', path: '/api/investments', description: 'Get user investments' },
            { method: 'POST', path: '/api/investments', description: 'Create investment' },
            { method: 'GET', path: '/api/transactions', description: 'Get transactions' },
            { method: 'GET', path: '/api/dashboard/stats', description: 'Dashboard statistics' },
            { method: 'POST', path: '/api/upload', description: 'File upload' },
            { method: 'GET', path: '/api/endpoints', description: 'List all endpoints' }
        ]
    });
});

// Root endpoint
app.get('/', (req, res) => {
    res.json({
        message: 'Welcome to Raw Wealthy Investment Platform API',
        version: '1.0.0',
        status: 'operational',
        documentation: 'Visit /api/endpoints for available routes',
        health: 'Visit /api/health for server status'
    });
});

// 404 handler
app.use((req, res) => {
    res.status(404).json({
        success: false,
        message: `Route ${req.originalUrl} not found`,
        suggestion: 'Visit /api/endpoints for available routes'
    });
});

// Error handler
app.use((err, req, res, next) => {
    console.error('Server error:', err.stack);
    res.status(500).json({
        success: false,
        message: 'Something went wrong!',
        error: process.env.NODE_ENV === 'development' ? err.message : 'Internal server error'
    });
});

// ============================================
// 6. START SERVER
// ============================================
app.listen(PORT, '0.0.0.0', () => {
    console.log(`✅ Server running on port ${PORT}`);
    console.log(`✅ Health check: http://0.0.0.0:${PORT}/api/health`);
    console.log(`✅ Test endpoint: http://0.0.0.0:${PORT}/api/plans`);
    console.log(`✅ Available at: https://real-wealthy-1.onrender.com`);
    console.log(`📊 Database status: ${mongoose.connection.readyState === 1 ? 'connected' : 'mock mode'}`);
});
