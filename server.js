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

// Create uploads directory if it doesn't exist
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
    fs.mkdirSync(uploadsDir, { recursive: true });
}

// Import middleware
const { protect, admin, requireKYC } = require('./src/middleware/auth');

const app = express();
const PORT = process.env.PORT || 10000;
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/raw-wealthy';

// Security middleware
app.use(helmet({
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false
}));
app.use(cors({
    origin: ['http://localhost:3000', 'https://rawwealthy.com', 'https://www.rawwealthy.com'],
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
}));

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // limit each IP to 100 requests per windowMs
    message: 'Too many requests from this IP, please try again later.'
});
app.use('/api/', limiter);

// Body parsing middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Compression
app.use(compression());

// Logging
if (process.env.NODE_ENV === 'development') {
    app.use(morgan('dev'));
} else {
    app.use(morgan('combined'));
}

// Static files
app.use('/uploads', express.static(uploadsDir));

// Database Connection
mongoose.connect(MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
})
.then(() => {
    console.log('✅ MongoDB connected successfully');
})
.catch((err) => {
    console.error('❌ MongoDB connection error:', err);
});

// Import models
require('./src/models/User');
require('./src/models/InvestmentPlan');
require('./src/models/Investment');
require('./src/models/Transaction');
require('./src/models/Deposit');
require('./src/models/Withdrawal');
require('./src/models/KYC');
require('./src/models/SupportTicket');
require('./src/models/Referral');
require('./src/models/Notification');

// Import controllers
const authController = require('./src/controllers/authController');
const userController = require('./src/controllers/userController');
const investmentController = require('./src/controllers/investmentController');
const transactionController = require('./src/controllers/transactionController');
const depositController = require('./src/controllers/depositController');
const withdrawalController = require('./src/controllers/withdrawalController');
const kycController = require('./src/controllers/kycController');
const supportController = require('./src/controllers/supportController');
const referralController = require('./src/controllers/referralController');
const adminController = require('./src/controllers/adminController');
const walletController = require('./src/controllers/walletController');
const notificationController = require('./src/controllers/notificationController');

// Health check endpoint
app.get('/api/health', (req, res) => {
    res.status(200).json({
        status: 'success',
        message: 'Raw Wealthy Backend is running',
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        environment: process.env.NODE_ENV,
        database: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected'
    });
});

// Debug endpoint to list all routes
app.get('/api/debug/paths', (req, res) => {
    const routes = [];
    app._router.stack.forEach((middleware) => {
        if (middleware.route) {
            routes.push({
                path: middleware.route.path,
                methods: Object.keys(middleware.route.methods)
            });
        } else if (middleware.name === 'router') {
            middleware.handle.stack.forEach((handler) => {
                if (handler.route) {
                    routes.push({
                        path: handler.route.path,
                        methods: Object.keys(handler.route.methods)
                    });
                }
            });
        }
    });
    res.json({ routes });
});

// Auth Routes
app.post('/api/auth/register', authController.register);
app.post('/api/auth/login', authController.login);
app.get('/api/auth/me', protect, authController.getMe);
app.post('/api/auth/forgot-password', authController.forgotPassword);
app.post('/api/auth/reset-password/:token', authController.resetPassword);
app.post('/api/auth/change-password', protect, authController.changePassword);
app.post('/api/auth/logout', protect, authController.logout);
app.post('/api/auth/two-factor/enable', protect, authController.enable2FA);
app.post('/api/auth/two-factor/verify', protect, authController.verify2FA);
app.post('/api/auth/two-factor/disable', protect, authController.disable2FA);
app.get('/api/auth/verify-email/:token', authController.verifyEmail);
app.post('/api/auth/verify-phone', protect, authController.verifyPhone);
app.post('/api/auth/resend-verification', authController.resendVerification);

// User Routes
app.get('/api/profile', protect, userController.getProfile);
app.put('/api/profile', protect, userController.updateProfile);
app.put('/api/profile/bank', protect, userController.updateBankDetails);
app.get('/api/dashboard/stats', protect, userController.getDashboardStats);

// Investment Routes
app.get('/api/plans', investmentController.getInvestmentPlans);
app.get('/api/plans/:id', investmentController.getInvestmentPlan);
app.get('/api/investments', protect, investmentController.getUserInvestments);
app.post('/api/investments', protect, investmentController.createInvestment);
app.get('/api/investments/:id', protect, investmentController.getInvestment);
app.post('/api/investments/:id/renew', protect, investmentController.renewInvestment);
app.post('/api/investments/:id/early-withdrawal', protect, investmentController.requestEarlyWithdrawal);
app.get('/api/investments/stats', protect, investmentController.getInvestmentStats);

// Transaction Routes
app.get('/api/transactions', protect, transactionController.getUserTransactions);
app.get('/api/transactions/:id', protect, transactionController.getTransaction);

// Deposit Routes
app.get('/api/deposits', protect, depositController.getUserDeposits);
app.post('/api/deposits', protect, depositController.createDeposit);
app.post('/api/deposits/:id/cancel', protect, depositController.cancelDeposit);

// Withdrawal Routes
app.get('/api/withdrawals', protect, withdrawalController.getUserWithdrawals);
app.post('/api/withdrawals', protect, withdrawalController.createWithdrawal);
app.post('/api/withdrawals/:id/cancel', protect, withdrawalController.cancelWithdrawal);

// KYC Routes
app.get('/api/kyc/status', protect, kycController.getKYCStatus);
app.post('/api/kyc', protect, kycController.submitKYC);
app.get('/api/kyc/:id', protect, kycController.getKYCDetails);

// Support Routes
app.get('/api/support/tickets', protect, supportController.getUserTickets);
app.post('/api/support', protect, supportController.createTicket);
app.get('/api/support/tickets/:id', protect, supportController.getTicket);
app.post('/api/support/tickets/:id/reply', protect, supportController.addReply);

// Referral Routes
app.get('/api/referrals/stats', protect, referralController.getReferralStats);
app.get('/api/referrals/list', protect, referralController.getReferralList);
app.get('/api/referrals/earnings', protect, referralController.getReferralEarnings);

// Admin Routes
app.get('/api/admin/dashboard', protect, admin, adminController.getDashboardStats);
app.get('/api/admin/users', protect, admin, adminController.getUsers);
app.get('/api/admin/users/:id', protect, admin, adminController.getUser);
app.put('/api/admin/users/:id', protect, admin, adminController.updateUser);
app.post('/api/admin/users/:id/adjust-balance', protect, admin, adminController.adjustUserBalance);
app.get('/api/admin/pending-investments', protect, admin, adminController.getPendingInvestments);
app.post('/api/admin/investments/:id/approve', protect, admin, adminController.approveInvestment);
app.post('/api/admin/investments/:id/reject', protect, admin, adminController.rejectInvestment);
app.get('/api/admin/pending-deposits', protect, admin, adminController.getPendingDeposits);
app.post('/api/admin/deposits/:id/approve', protect, admin, adminController.approveDeposit);
app.post('/api/admin/deposits/:id/reject', protect, admin, adminController.rejectDeposit);
app.get('/api/admin/pending-withdrawals', protect, admin, adminController.getPendingWithdrawals);
app.post('/api/admin/withdrawals/:id/approve', protect, admin, adminController.approveWithdrawal);
app.post('/api/admin/withdrawals/:id/reject', protect, admin, adminController.rejectWithdrawal);
app.get('/api/admin/pending-kyc', protect, admin, adminController.getPendingKYC);
app.post('/api/admin/kyc/:id/approve', protect, admin, adminController.approveKYC);
app.post('/api/admin/kyc/:id/reject', protect, admin, adminController.rejectKYC);
app.post('/api/admin/notifications/send', protect, admin, adminController.sendNotification);
app.get('/api/admin/logs', protect, admin, adminController.getAdminLogs);

// Wallet Routes
app.get('/api/wallet', protect, walletController.getWallet);
app.post('/api/wallet/transfer', protect, walletController.transferFunds);
app.get('/api/wallet/transactions', protect, walletController.getWalletTransactions);

// Notification Routes
app.get('/api/notifications', protect, notificationController.getNotifications);
app.post('/api/notifications/:id/read', protect, notificationController.markAsRead);
app.delete('/api/notifications/:id', protect, notificationController.deleteNotification);

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
const upload = multer({ storage: storage });

app.post('/api/upload', protect, upload.single('file'), (req, res) => {
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

// 404 handler
app.use((req, res) => {
    res.status(404).json({
        success: false,
        message: `Route ${req.originalUrl} not found`
    });
});

// Error handling middleware
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
            message: 'Unauthorized: Invalid token'
        });
    }
    
    res.status(err.status || 500).json({
        success: false,
        message: err.message || 'Internal server error',
        ...(process.env.NODE_ENV === 'development' && { stack: err.stack })
    });
});

// Start server
app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 Server running on port ${PORT}`);
    console.log(`📁 Environment: ${process.env.NODE_ENV || 'development'}`);
    console.log(`🗄️ Database: ${MONGODB_URI}`);
    console.log(`📁 Uploads directory: ${uploadsDir}`);
    console.log(`✅ Health check: http://localhost:${PORT}/api/health`);
    console.log(`✅ Debug routes: http://localhost:${PORT}/api/debug/paths`);
});

module.exports = app;
