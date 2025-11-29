import fetch from 'node-fetch';

const HEALTH_CHECK_URL = process.env.RENDER_HEALTH_CHECK_URL || 'http://localhost:10000/health';

async function checkHealth() {
  try {
    console.log('🔍 Performing health check...');
    
    const response = await fetch(HEALTH_CHECK_URL, {
      timeout: 10000,
      headers: {
        'User-Agent': 'Raw-Wealthy-Health-Check/1.0'
      }
    });
    
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}: ${response.statusText}`);
    }
    
    const data = await response.json();
    
    if (data.success && data.database === 'connected') {
      console.log('✅ Health check PASSED');
      console.log(`📊 Database: ${data.database}`);
      console.log(`🌐 Environment: ${data.environment}`);
      console.log(`⏰ Uptime: ${Math.floor(data.uptime)} seconds`);
      process.exit(0);
    } else {
      throw new Error('Health check response indicates failure');
    }
  } catch (error) {
    console.error('❌ Health check FAILED:', error.message);
    process.exit(1);
  }
}

checkHealth();
