const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const helmet = require('helmet');
const compression = require('compression');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
const mongoSanitize = require('express-mongo-sanitize');
const dotenv = require('dotenv');
const http = require('http');
const path = require('path');
const fs = require('fs');

// Load environment variables FIRST
dotenv.config();

// ============================================
// DYNAMIC PATH RESOLUTION - FIX FOR RENDER
// ============================================
console.log('🔄 Current directory:', __dirname);
console.log('🔄 Process CWD:', process.cwd());

// Function to safely require modules with fallback paths
function safeRequire(modulePath) {
  const possiblePaths = [
    // Try relative to current file
    path.join(__dirname, modulePath),
    // Try from project root (if server.js is in src/)
    path.join(process.cwd(), modulePath),
    // Try without 'src/' prefix (if server.js is in src/)
    path.join(__dirname, modulePath.replace('src/', '')),
    // Try with 'src/' prefix (if server.js is in root)
    path.join(__dirname, 'src', modulePath),
  ];

  for (const fullPath of possiblePaths) {
    try {
      const module = require(fullPath);
      console.log(`✅ Loaded module: ${modulePath} from ${fullPath}`);
      return module;
    } catch (err) {
      // Continue to next path
    }
  }
  
  throw new Error(`Cannot find module: ${modulePath}. Tried: ${possiblePaths.join(', ')}`);
}

// ============================================
// MANUALLY CHECK AND LOAD MODULES
// ============================================
console.log('\n🔍 Checking for required modules...');

// List all files in current directory for debugging
try {
  const files = fs.readdirSync(__dirname);
  console.log('📁 Files in current directory:', files);
  
  if (fs.existsSync(path.join(__dirname, 'routes'))) {
    console.log('📁 Routes folder exists:', fs.readdirSync(path.join(__dirname, 'routes')));
  }
  
  if (fs.existsSync(path.join(process.cwd(), 'routes'))) {
    console.log('📁 Routes in root:', fs.readdirSync(path.join(process.cwd(), 'routes')));
  }
} catch (err) {
  console.log('⚠️ Could not list directory:', err.message);
}

// ============================================
// LOAD CONFIGURATION FIRST
// ============================================
let connectDB;
try {
  // Try different possible locations for database config
  if (fs.existsSync(path.join(__dirname, 'config', 'database.js'))) {
    connectDB = require('./config/database');
  } else if (fs.existsSync(path.join(process.cwd(), 'src', 'config', 'database.js'))) {
    connectDB = require('./src/config/database');
  } else if (fs.existsSync(path.join(process.cwd(), 'config', 'database.js'))) {
    connectDB = require('./config/database');
  } else {
    console.log('⚠️ Database config not found, will try to load dynamically');
    // Will attempt to load later
  }
} catch (err) {
  console.log('⚠️ Could not load database config:', err.message);
}

// ============================================
// INITIALIZE EXPRESS APP
// ============================================
const app = express();
const server = http.createServer(app);

// Basic middleware that doesn't require external modules
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Security middleware
app.use(helmet());
app.use(cors({
  origin: process.env.FRONTEND_URL || '*',
  credentials: true
}));

// Rate limiting
app.use('/api/', rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: 'Too many requests'
}));

// Logging
if (process.env.NODE_ENV === 'development') {
  const morgan = require('morgan');
  app.use(morgan('dev'));
}

// Health endpoint (NO external dependencies)
app.get('/api/health', (req, res) => {
  res.status(200).json({
    status: 'running',
    timestamp: new Date().toISOString(),
    node: process.version,
    memory: process.memoryUsage(),
    uptime: process.uptime()
  });
});

// ============================================
// DYNAMICALLY LOAD ROUTES IF THEY EXIST
// ============================================
const routesToLoad = [
  { path: 'authRoutes', route: '/api/auth' },
  { path: 'userRoutes', route: '/api/users' },
  { path: 'investmentRoutes', route: '/api/investments' },
  { path: 'transactionRoutes', route: '/api/transactions' },
  { path: 'depositRoutes', route: '/api/deposits' },
  { path: 'withdrawalRoutes', route: '/api/withdrawals' },
  { path: 'kycRoutes', route: '/api/kyc' },
  { path: 'supportRoutes', route: '/api/support' },
  { path: 'referralRoutes', route: '/api/referrals' },
  { path: 'adminRoutes', route: '/api/admin' },
  { path: 'walletRoutes', route: '/api/wallets' },
  { path: 'notificationRoutes', route: '/api/notifications' }
];

routesToLoad.forEach(({ path: routePath, route: endpoint }) => {
  try {
    // Try multiple possible locations
    let routeModule;
    
    // Option 1: Directly in routes folder (if server.js is in src/)
    if (fs.existsSync(path.join(__dirname, 'routes', `${routePath}.js`))) {
      routeModule = require(`./routes/${routePath}`);
    }
    // Option 2: In src/routes (if server.js is in root)
    else if (fs.existsSync(path.join(__dirname, 'src', 'routes', `${routePath}.js`))) {
      routeModule = require(`./src/routes/${routePath}`);
    }
    // Option 3: In project root routes
    else if (fs.existsSync(path.join(process.cwd(), 'routes', `${routePath}.js`))) {
      routeModule = require(path.join(process.cwd(), 'routes', routePath));
    }
    
    if (routeModule) {
      app.use(endpoint, routeModule);
      console.log(`✅ Loaded route: ${endpoint}`);
    } else {
      console.log(`⚠️ Skipped route (not found): ${endpoint}`);
    }
  } catch (err) {
    console.log(`⚠️ Error loading route ${endpoint}:`, err.message);
  }
});

// ============================================
// BASIC ROUTES FOR TESTING
// ============================================
app.get('/', (req, res) => {
  res.json({
    message: 'Raw Wealthy Backend API',
    status: 'operational',
    version: '1.0.0',
    endpoints: routesToLoad.map(r => r.route)
  });
});

app.get('/api/debug/paths', (req, res) => {
  res.json({
    __dirname: __dirname,
    process_cwd: process.cwd(),
    env: process.env.NODE_ENV,
    files_in_current_dir: fs.readdirSync(__dirname),
    exists_src_folder: fs.existsSync(path.join(__dirname, 'src')),
    exists_routes_folder: fs.existsSync(path.join(__dirname, 'routes'))
  });
});

// ============================================
// CONNECT TO DATABASE
// ============================================
async function initializeDatabase() {
  if (!connectDB) {
    try {
      // Try to load database config dynamically
      const dbPaths = [
        './config/database',
        './src/config/database',
        '../config/database',
        '../src/config/database'
      ];
      
      for (const dbPath of dbPaths) {
        try {
          connectDB = require(dbPath);
          console.log(`✅ Loaded database config from: ${dbPath}`);
          break;
        } catch (e) {
          // Continue
        }
      }
    } catch (err) {
      console.log('⚠️ Could not load database module:', err.message);
    }
  }
  
  if (connectDB && typeof connectDB === 'function') {
    try {
      await connectDB();
      console.log('✅ Database connected');
      return true;
    } catch (err) {
      console.log('⚠️ Database connection failed:', err.message);
      return false;
    }
  } else {
    console.log('⚠️ No database connection function available');
    return false;
  }
}

// ============================================
// START SERVER
// ============================================
const PORT = process.env.PORT || 10000;

async function startServer() {
  console.log('\n🚀 Starting Raw Wealthy Backend...');
  console.log(`📁 Server location: ${__dirname}`);
  console.log(`🌐 Port: ${PORT}`);
  console.log(`⚙️ Environment: ${process.env.NODE_ENV || 'development'}`);
  
  // Try to connect to database (non-blocking)
  initializeDatabase().then(connected => {
    if (connected) {
      console.log('✅ Database initialized');
    } else {
      console.log('⚠️ Starting without database connection');
    }
  });
  
  server.listen(PORT, '0.0.0.0', () => {
    console.log(`✅ Server running on http://0.0.0.0:${PORT}`);
    console.log(`✅ Health check: http://0.0.0.0:${PORT}/api/health`);
    console.log(`✅ Debug info: http://0.0.0.0:${PORT}/api/debug/paths`);
  });
}

startServer().catch(err => {
  console.error('💥 Failed to start server:', err);
  process.exit(1);
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('👋 SIGTERM received');
  server.close(() => {
    console.log('💤 Server closed');
    process.exit(0);
  });
});

process.on('uncaughtException', (err) => {
  console.error('💥 Uncaught Exception:', err);
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('💥 Unhandled Rejection at:', promise, 'reason:', reason);
});
