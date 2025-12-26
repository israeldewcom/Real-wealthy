require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 10000;

console.log('🚀 Starting Raw Wealthy Backend...');

// ============================================
// 1. BASIC MIDDLEWARE
// ============================================
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(cors());
app.use(helmet());
app.use(morgan('dev'));

// ============================================
// 2. HEALTH CHECK ENDPOINT
// ============================================
app.get('/api/health', (req, res) => {
    res.json({
        success: true,
        message: 'Raw Wealthy Backend is running',
        timestamp: new Date().toISOString(),
        environment: process.env.NODE_ENV || 'production',
        version: '1.0.0'
    });
});

// ============================================
// 3. AUTH ENDPOINTS (MUST EXACT MATCH FRONTEND)
// ============================================

// REGISTER - EXACTLY what frontend expects
app.post('/api/auth/register', (req, res) => {
    console.log('📝 Register request received:', req.body);
    
    const { full_name, email, phone, password } = req.body;
    
    if (!full_name || !email || !phone || !password) {
        return res.status(400).json({
            success: false,
            message: 'All fields are required'
        });
    }
    
    // Mock user response
    const mockUser = {
        _id: 'user_' + Date.now(),
        full_name,
        email,
        phone,
        balance: 0,
        referral_code: 'REF' + Math.random().toString(36).substr(2, 6).toUpperCase(),
        kyc_status: 'not_submitted',
        role: 'user',
        created_at: new Date().toISOString()
    };
    
    const mockToken = 'jwt_token_' + Date.now();
    
    res.status(201).json({
        success: true,
        message: 'Registration successful',
        data: {
            token: mockToken,
            user: mockUser
        }
    });
});

// LOGIN - EXACTLY what frontend expects
app.post('/api/auth/login', (req, res) => {
    console.log('🔐 Login request received:', req.body);
    
    const { email, password } = req.body;
    
    if (!email || !password) {
        return res.status(400).json({
            success: false,
            message: 'Email and password are required'
        });
    }
    
    // Mock user response
    const mockUser = {
        _id: 'user_123456',
        full_name: 'Demo User',
        email: email,
        phone: '+2348123456789',
        balance: 50000,
        total_earnings: 15000,
        referral_earnings: 5000,
        referral_code: 'DEMO123',
        kyc_status: 'verified',
        role: 'user',
        created_at: new Date().toISOString()
    };
    
    const mockToken = 'jwt_token_' + Date.now();
    
    res.json({
        success: true,
        message: 'Login successful',
        data: {
            token: mockToken,
            user: mockUser
        }
    });
});

// PROFILE - EXACTLY what frontend expects
app.get('/api/profile', (req, res) => {
    console.log('👤 Profile request received');
    
    // Mock user data
    const mockUser = {
        _id: 'user_123456',
        full_name: 'Demo User',
        email: 'demo@rawwealthy.com',
        phone: '+2348123456789',
        balance: 50000,
        total_earnings: 15000,
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

// ============================================
// 4. INVESTMENT ENDPOINTS
// ============================================

// GET PLANS - EXACTLY what frontend expects
app.get('/api/plans', (req, res) => {
    const plans = [
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
        }
    ];
    
    res.json({
        success: true,
        count: plans.length,
        data: { plans }
    });
});

// CREATE INVESTMENT - EXACTLY what frontend expects
app.post('/api/investments', (req, res) => {
    console.log('💰 Investment request received:', req.body);
    
    const { plan_id, amount } = req.body;
    
    if (!plan_id || !amount) {
        return res.status(400).json({
            success: false,
            message: 'Plan ID and amount are required'
        });
    }
    
    // Mock investment response
    const mockInvestment = {
        _id: 'inv_' + Date.now(),
        plan: { _id: plan_id, name: 'Cocoa Beans' },
        amount: amount,
        status: 'pending',
        created_at: new Date().toISOString()
    };
    
    res.status(201).json({
        success: true,
        message: 'Investment request submitted successfully',
        data: { investment: mockInvestment }
    });
});

// GET INVESTMENTS - EXACTLY what frontend expects
app.get('/api/investments', (req, res) => {
    const investments = [
        {
            _id: 'inv_1',
            plan: { name: 'Cocoa Beans', daily_interest: 2.5 },
            amount: 3500,
            status: 'active',
            remaining_days: 25,
            total_earned: 875,
            created_at: new Date(Date.now() - 5 * 86400000).toISOString()
        },
        {
            _id: 'inv_2',
            plan: { name: 'Gold', daily_interest: 3.2 },
            amount: 50000,
            status: 'active',
            remaining_days: 15,
            total_earned: 24000,
            created_at: new Date(Date.now() - 15 * 86400000).toISOString()
        }
    ];
    
    res.json({
        success: true,
        data: { investments }
    });
});

// ============================================
// 5. TRANSACTION ENDPOINTS
// ============================================

app.get('/api/transactions', (req, res) => {
    const transactions = [
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
            description: 'Investment in Cocoa Beans',
            status: 'completed',
            created_at: new Date(Date.now() - 86400000).toISOString()
        }
    ];
    
    res.json({
        success: true,
        data: { transactions }
    });
});

// ============================================
// 6. DASHBOARD ENDPOINT
// ============================================

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
                { date: new Date().toISOString().split('T')[0], earnings: 720 },
                { date: new Date(Date.now() - 86400000).toISOString().split('T')[0], earnings: 750 },
                { date: new Date(Date.now() - 2 * 86400000).toISOString().split('T')[0], earnings: 780 }
            ],
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
                    description: 'Bank Transfer Deposit',
                    amount: 50000,
                    created_at: new Date().toISOString()
                }
            ]
        }
    });
});

// ============================================
// 7. OTHER ESSENTIAL ENDPOINTS
// ============================================

// UPLOAD
const multer = require('multer');
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        const uploadsDir = path.join(__dirname, 'uploads');
        if (!fs.existsSync(uploadsDir)) {
            fs.mkdirSync(uploadsDir, { recursive: true });
        }
        cb(null, uploadsDir);
    },
    filename: function (req, file, cb) {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
    }
});
const upload = multer({ storage: storage });

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
            filename: req.file.filename
        }
    });
});

// DEPOSIT
app.post('/api/deposits', (req, res) => {
    console.log('💳 Deposit request:', req.body);
    
    const mockDeposit = {
        _id: 'dep_' + Date.now(),
        amount: req.body.amount,
        status: 'pending',
        created_at: new Date().toISOString()
    };
    
    res.status(201).json({
        success: true,
        message: 'Deposit request submitted',
        data: { deposit: mockDeposit }
    });
});

// WITHDRAWAL
app.post('/api/withdrawals', (req, res) => {
    console.log('💸 Withdrawal request:', req.body);
    
    const mockWithdrawal = {
        _id: 'wth_' + Date.now(),
        amount: req.body.amount,
        platform_fee: req.body.amount * 0.05,
        net_amount: req.body.amount * 0.95,
        status: 'pending',
        created_at: new Date().toISOString()
    };
    
    res.status(201).json({
        success: true,
        message: 'Withdrawal request submitted',
        data: { withdrawal: mockWithdrawal }
    });
});

// ============================================
// 8. ROOT AND DEBUG ENDPOINTS
// ============================================

app.get('/', (req, res) => {
    res.json({
        message: 'Raw Wealthy API v1.0',
        status: 'operational',
        endpoints: [
            'POST /api/auth/register',
            'POST /api/auth/login',
            'GET  /api/profile',
            'GET  /api/plans',
            'POST /api/investments',
            'GET  /api/investments',
            'GET  /api/transactions',
            'GET  /api/dashboard/stats',
            'POST /api/upload',
            'POST /api/deposits',
            'POST /api/withdrawals'
        ]
    });
});

app.get('/api/debug', (req, res) => {
    res.json({
        server: 'Raw Wealthy Backend',
        status: 'running',
        port: PORT,
        timestamp: new Date().toISOString(),
        routes: [
            '/api/health',
            '/api/auth/register',
            '/api/auth/login',
            '/api/profile',
            '/api/plans',
            '/api/investments',
            '/api/dashboard/stats'
        ]
    });
});

// ============================================
// 9. ERROR HANDLING
// ============================================

app.use((req, res) => {
    res.status(404).json({
        success: false,
        message: `Route ${req.originalUrl} not found`,
        availableRoutes: [
            'GET  /api/health',
            'POST /api/auth/register',
            'POST /api/auth/login',
            'GET  /api/profile',
            'GET  /api/plans',
            'POST /api/investments',
            'GET  /api/investments',
            'GET  /api/dashboard/stats',
            'POST /api/upload'
        ]
    });
});

// ============================================
// 10. START SERVER
// ============================================
app.listen(PORT, '0.0.0.0', () => {
    console.log(`✅ Server running on port ${PORT}`);
    console.log(`✅ Health check: http://0.0.0.0:${PORT}/api/health`);
    console.log(`✅ Login: POST http://0.0.0.0:${PORT}/api/auth/login`);
    console.log(`✅ Available at: https://real-wealthy-1.onrender.com`);
    console.log(`📊 Server ready for connections`);
});
