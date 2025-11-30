app.get('/health', async (req, res) => {
  const dbStatus = mongoose.connection.readyState;
  const statusMap = { 
    0: 'disconnected', 
    1: 'connected', 
    2: 'connecting', 
    3: 'disconnecting' 
  };
  
  // Get MongoDB connection details (masked for security)
  const mongoUri = process.env.MONGODB_URI || 'not-set';
  const maskedUri = mongoUri.replace(/mongodb\+srv:\/\/([^:]+):([^@]+)@/, 'mongodb+srv://$1:****@');
  
  const healthCheck = {
    success: dbStatus === 1,
    status: dbStatus === 1 ? 'OK' : 'Database Connecting',
    message: dbStatus === 1 ? '🚀 API fully operational' : 'Database connection in progress',
    timestamp: new Date().toISOString(),
    database: statusMap[dbStatus],
    database_status: dbStatus,
    environment: process.env.NODE_ENV,
    version: '31.0.0',
    debug_info: {
      mongo_uri_configured: !!process.env.MONGODB_URI,
      mongo_uri_length: mongoUri.length,
      jwt_secret_configured: !!process.env.JWT_SECRET,
      admin_password_configured: !!process.env.ADMIN_PASSWORD
    }
  };

  res.status(dbStatus === 1 ? 200 : 503).json(healthCheck);
});
