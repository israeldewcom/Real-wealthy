const mongoose = require('mongoose');
const winston = require('winston');

// Create logger
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({ filename: 'logs/database-error.log', level: 'error' }),
    new winston.transports.File({ filename: 'logs/database.log' })
  ]
});

if (process.env.NODE_ENV !== 'production') {
  logger.add(new winston.transports.Console({
    format: winston.format.simple()
  }));
}

const connectDB = async () => {
  try {
    const conn = await mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/raw-wealthy', {
      useNewUrlParser: true,
      useUnifiedTopology: true,
      serverSelectionTimeoutMS: 5000,
      socketTimeoutMS: 45000,
      maxPoolSize: 10,
      retryWrites: true,
      writeConcern: {
        w: 'majority'
      }
    });

    logger.info(`MongoDB Connected: ${conn.connection.host}`);

    // Connection events
    mongoose.connection.on('connected', () => {
      logger.info('Mongoose connected to DB');
    });

    mongoose.connection.on('error', (err) => {
      logger.error(`Mongoose connection error: ${err}`);
    });

    mongoose.connection.on('disconnected', () => {
      logger.warn('Mongoose disconnected from DB');
    });

    // Close mongoose connection when app terminates
    process.on('SIGINT', async () => {
      await mongoose.connection.close();
      logger.info('Mongoose connection closed through app termination');
      process.exit(0);
    });

    return conn;
  } catch (error) {
    logger.error(`MongoDB connection error: ${error.message}`);
    process.exit(1);
  }
};

// Optimize indexes
const optimizeIndexes = async () => {
  try {
    const collections = await mongoose.connection.db.collections();
    
    for (const collection of collections) {
      await collection.createIndexes();
    }
    
    logger.info('Database indexes optimized');
  } catch (error) {
    logger.error(`Index optimization error: ${error.message}`);
  }
};

// Database health check
const checkDBHealth = async () => {
  try {
    const result = await mongoose.connection.db.admin().ping();
    return {
      status: 'healthy',
      message: 'Database is responding',
      timestamp: new Date()
    };
  } catch (error) {
    return {
      status: 'unhealthy',
      message: error.message,
      timestamp: new Date()
    };
  }
};

// Backup database
const backupDatabase = async () => {
  try {
    const { exec } = require('child_process');
    const { promisify } = require('util');
    const execAsync = promisify(exec);
    
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const backupPath = `backups/backup-${timestamp}.gz`;
    
    const command = `mongodump --uri="${process.env.MONGODB_URI}" --gzip --archive=${backupPath}`;
    
    await execAsync(command);
    logger.info(`Database backup created: ${backupPath}`);
    
    return backupPath;
  } catch (error) {
    logger.error(`Database backup error: ${error.message}`);
    throw error;
  }
};

module.exports = {
  connectDB,
  optimizeIndexes,
  checkDBHealth,
  backupDatabase
};
