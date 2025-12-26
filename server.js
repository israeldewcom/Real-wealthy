
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

// ============================================
// 1. MIDDLEWARE
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
    message: 'Too many requests'
});
app.use('/api/', limiter);

// ============================================
// 2. DATABASE (OPTIONAL)
// ============================================
const MONGODB_URI = process.env.MONGODB_URI;
if (MONGODB_URI && !MONGODB_URI.includes('your-')) {
    mongoose.connect(MONGODB_URI)
    .then(() => console.log('✅ MongoDB connected'))
    .catch(err => console.log('❌ MongoDB error:', err.message));
} else {
    console.log('⚠️ Running in mock mode (no DB)');
}

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
    }
];

// ============================================
// 4. ALL ROUTES
// ============================================

// 4.1 HEALTH
app.get('/api/health', (req, res) => {
    res.json({
        success: true,
        message: 'Raw Wealthy Backend is running',
        timestamp: new Date().toISOString(),
        environment: process.env.NODE_ENV || 'development',
        version: '1.0.0'
    });
});

// 4.2 DEBUG
app.get('/api/debug', (req, res) => {
    res.json({
        server: 'Raw Wealthy Backend',
        status: 'running',
        port: PORT,
        routes: [
            '/api/health',
            '/api/debug',
            '/api/plans',
            '/api/auth/register',
            '/api/auth/login',
            '/api/profile',
            '/api/dashboard/stats',
            '/api/investments',
            '/api/transactions',
            '/api/deposits',
            '/api/withdrawals',
            '/api/kyc/status',
            '/api/kyc',
            '/api/support/tickets',
            '/api/support',
            '/api/referrals/stats',
            '/api/referrals/list',
            '/api/admin/dashboard',
            '/api/upload',
            '/api/endpoints'
        ]
    });
});

// 4.3 PLANS
app.get('/api/plans', (req, res) => {
    res.json({
        success: true,
        count: mockPlans.length,
        data: { plans: mockPlans }
    });
});

app.get('/api/plans/:id', (req, res) => {
    const plan = mockPlans.find(p => p._id === req.params.id);
    if (!plan) {
        return res.status(404).json({ success: false, message: 'Plan not found' });
    }
    res.json({ success: true, data: { plan } });
});

// 4.4 AUTH
app.post('/api/auth/register', (req, res) => {
    const { full_name, email, phone, password } = req.body;
    
    if (!full_name || !email || !phone || !password) {
        return res.status(400).json({ 
            success: false, 
            message: 'All fields are required' 
        });
    }
    
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
    
    const mockToken = 'jwt_' + Date.now();
    
    res.status(201).json({
        success: true,
        message: 'Registration successful',
        data: { token: mockToken, user: mockUser }
    });
});

// ✅ THIS IS THE FIX - ADD POST /api/auth/login
app.post('/api/auth/login', (req, res) => {
    console.log('📥 Login attempt:', req.body);
    
    const { email, password } = req.body;
    
    if (!email || !password) {
        return res.status(400).json({ 
            success: false, 
            message: 'Email and password required' 
        });
    }
    
    const mockUser = {
        _id: 'user_123',
        full_name: 'Demo User',
        email,
        phone: '+2348123456789',
        balance: 50000,
        referral_code: 'DEMO123',
        kyc_status: 'verified',
        role: 'user',
        created_at: new Date().toISOString()
    };
    
    const mockToken = 'jwt_token_' + Date.now();
    
    console.log('✅ Login successful for:', email);
    
    res.json({
        success: true,
        message: 'Login successful',
        data: {
            token: mockToken,
            user: mockUser
        }
    });
});

// 4.5 PROFILE
app.get('/api/profile', (req, res) => {
    const token = req.headers.authorization;
    
    if (!token) {
        return res.status(401).json({ 
            success: false, 
            message: 'No token provided' 
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
        created_at: new Date().toISOString()
    };
    
    res.json({ success: true, data: { user: mockUser } });
});

app.put('/api/profile', (req, res) => {
    res.json({ 
        success: true, 
        message: 'Profile updated',
        data: { user: req.body }
    });
});

// 4.6 DASHBOARD
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
            }
        }
    });
});

// 4.7 INVESTMENTS
app.get('/api/investments', (req, res) => {
    res.json({
        success: true,
        data: {
            investments: [
                {
                    _id: 'inv_1',
                    plan: mockPlans[0],
                    amount: 3500,
                    status: 'active',
                    total_earned: 875
                }
            ]
        }
    });
});

app.post('/api/investments', (req, res) => {
    res.status(201).json({
        success: true,
        message: 'Investment created',
        data: {
            investment: {
                _id: 'inv_' + Date.now(),
                ...req.body,
                status: 'pending'
            }
        }
    });
});

// 4.8 TRANSACTIONS
app.get('/api/transactions', (req, res) => {
    res.json({
        success: true,
        data: {
            transactions: [
                {
                    _id: 'txn_1',
                    type: 'deposit',
                    amount: 50000,
                    description: 'Bank Transfer',
                    status: 'completed'
                }
            ]
        }
    });
});

// 4.9 DEPOSITS
app.get('/api/deposits', (req, res) => {
    res.json({
        success: true,
        data: { deposits: [] }
    });
});

app.post('/api/deposits', (req, res) => {
    res.status(201).json({
        success: true,
        message: 'Deposit submitted',
        data: { deposit: req.body }
    });
});

// 4.10 WITHDRAWALS
app.get('/api/withdrawals', (req, res) => {
    res.json({
        success: true,
        data: { withdrawals: [] }
    });
});

app.post('/api/withdrawals', (req, res) => {
    res.status(201).json({
        success: true,
        message: 'Withdrawal submitted',
        data: { withdrawal: req.body }
    });
});

// 4.11 KYC
app.get('/api/kyc/status', (req, res) => {
    res.json({
        success: true,
        status: 'verified',
        message: 'KYC is verified'
    });
});

app.post('/api/kyc', (req, res) => {
    res.json({
        success: true,
        message: 'KYC submitted'
    });
});

// 4.12 SUPPORT
app.get('/api/support/tickets', (req, res) => {
    res.json({
        success: true,
        data: { tickets: [] }
    });
});

app.post('/api/support', (req, res) => {
    res.json({
        success: true,
        message: 'Support ticket submitted'
    });
});

// 4.13 REFERRALS
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

app.get('/api/referrals/list', (req, res) => {
    res.json({
        success: true,
        data: { referrals: [] }
    });
});

// 4.14 ADMIN
app.get('/api/admin/dashboard', (req, res) => {
    // Check admin token
    const token = req.headers.authorization;
    
    if (token && token.includes('admin')) {
        res.json({
            success: true,
            data: {
                stats: {
                    total_users: 100,
                    total_investments: 2500000,
                    total_withdrawals: 500000,
                    platform_earnings: 25000
                }
            }
        });
    } else {
        res.status(403).json({
            success: false,
            message: 'Admin access required'
        });
    }
});

// 4.15 FILE UPLOAD
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
    fs.mkdirSync(uploadsDir, { recursive: true });
}

const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, uploadsDir),
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
    }
});

const upload = multer({ storage, limits: { fileSize: 5 * 1024 * 1024 } });

app.post('/api/upload', upload.single('file'), (req, res) => {
    if (!req.file) {
        return res.status(400).json({
            success: false,
            message: 'No file uploaded'
        });
    }
    
    res.json({
        success: true,
        message: 'File uploaded',
        data: {
            fileUrl: `/uploads/${req.file.filename}`,
            filename: req.file.filename
        }
    });
});

// 4.16 ENDPOINTS LIST
app.get('/api/endpoints', (req, res) => {
    res.json({
        success: true,
        endpoints: [
            { method: 'GET', path: '/api/health', description: 'Health check' },
            { method: 'GET', path: '/api/debug', description: 'Debug info' },
            { method: 'GET', path: '/api/plans', description: 'Investment plans' },
            { method: 'POST', path: '/api/auth/register', description: 'Register user' },
            { method: 'POST', path: '/api/auth/login', description: 'Login user' },
            { method: 'GET', path: '/api/profile', description: 'User profile' },
            { method: 'GET', path: '/api/dashboard/stats', description: 'Dashboard' },
            { method: 'GET', path: '/api/investments', description: 'User investments' },
            { method: 'POST', path: '/api/investments', description: 'Create investment' },
            { method: 'GET', path: '/api/transactions', description: 'Transactions' },
            { method: 'POST', path: '/api/upload', description: 'File upload' },
            { method: 'GET', path: '/api/endpoints', description: 'All endpoints' }
        ]
    });
});

// ============================================
// 5. ROOT AND 404
// ============================================
app.get('/', (req, res) => {
    res.json({
        message: 'Raw Wealthy Investment Platform API',
        version: '1.0.0',
        status: 'operational',
        docs: 'https://real-wealthy-1.onrender.com/api/endpoints'
    });
});

// 404 Handler
app.use((req, res) => {
    res.status(404).json({
        success: false,
        message: `Route ${req.originalUrl} not found`,
        suggestion: 'Visit /api/endpoints for available routes',
        availableRoutes: [
            'GET  /api/health',
            'GET  /api/debug',
            'GET  /api/plans',
            'POST /api/auth/register',
            'POST /api/auth/login',
            'GET  /api/profile',
            'GET  /api/dashboard/stats',
            'GET  /api/investments',
            'POST /api/investments',
            'GET  /api/transactions',
            'GET  /api/deposits',
            'POST /api/deposits',
            'GET  /api/withdrawals',
            'POST /api/withdrawals',
            'GET  /api/kyc/status',
            'POST /api/kyc',
            'GET  /api/support/tickets',
            'POST /api/support',
            'GET  /api/referrals/stats',
            'GET  /api/referrals/list',
            'GET  /api/admin/dashboard',
            'POST /api/upload',
            'GET  /api/endpoints'
        ]
    });
});

// ============================================
// 6. START SERVER
// ============================================
app.listen(PORT, '0.0.0.0', () => {
    console.log(`✅ Server running on port ${PORT}`);
    console.log(`✅ Available at: https://real-wealthy-1.onrender.com`);
    console.log(`✅ Health: https://real-wealthy-1.onrender.com/api/health`);
    console.log(`✅ Login: POST https://real-wealthy-1.onrender.com/api/auth/login`);
    console.log(`✅ Plans: https://real-wealthy-1.onrender.com/api/plans`);
});
