import mongoose from 'mongoose';
import jwt from 'jsonwebtoken';

const TEST_CONFIG = {
  MONGODB_URI: process.env.MONGODB_URI,
  JWT_SECRET: process.env.JWT_SECRET || 'test-secret',
  PORT: process.env.PORT || 10000
};

async function testDatabaseConnection() {
  console.log('🔄 Testing database connection...');
  
  try {
    await mongoose.connect(TEST_CONFIG.MONGODB_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
      serverSelectionTimeoutMS: 5000,
      socketTimeoutMS: 45000,
    });
    
    console.log('✅ Database connection: SUCCESS');
    
    // Test basic operations
    const testDoc = new mongoose.models.Test({ name: 'connection-test' });
    await testDoc.save();
    await mongoose.models.Test.deleteOne({ name: 'connection-test' });
    
    console.log('✅ Database operations: SUCCESS');
    await mongoose.connection.close();
    return true;
  } catch (error) {
    console.error('❌ Database connection: FAILED', error.message);
    return false;
  }
}

async function testJWT() {
  console.log('🔄 Testing JWT functionality...');
  
  try {
    const payload = { id: 'test-user', role: 'user' };
    const token = jwt.sign(payload, TEST_CONFIG.JWT_SECRET, { expiresIn: '1h' });
    const decoded = jwt.verify(token, TEST_CONFIG.JWT_SECRET);
    
    if (decoded.id === 'test-user') {
      console.log('✅ JWT functionality: SUCCESS');
      return true;
    }
  } catch (error) {
    console.error('❌ JWT functionality: FAILED', error.message);
    return false;
  }
}

async function runAllTests() {
  console.log('🚀 Starting deployment tests...\n');
  
  const tests = [
    await testDatabaseConnection(),
    await testJWT()
  ];
  
  const passed = tests.filter(Boolean).length;
  const total = tests.length;
  
  console.log(`\n📊 Test Results: ${passed}/${total} passed`);
  
  if (passed === total) {
    console.log('🎉 All tests passed! Ready for deployment.');
    process.exit(0);
  } else {
    console.log('❌ Some tests failed. Please check configuration.');
    process.exit(1);
  }
}

// Create a test model if it doesn't exist
if (!mongoose.models.Test) {
  mongoose.model('Test', new mongoose.Schema({ name: String }));
}

runAllTests();
