const mongoose = require('mongoose');
const User = require('./src/models/User');
const InvestmentPlan = require('./src/models/InvestmentPlan');

const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/raw-wealthy';

async function seedDatabase() {
    try {
        await mongoose.connect(MONGODB_URI);
        console.log('✅ Connected to MongoDB');

        // Clear existing data
        await User.deleteMany({});
        await InvestmentPlan.deleteMany({});

        // Create admin user
        const admin = await User.create({
            full_name: 'Admin User',
            email: 'admin@rawwealthy.com',
            phone: '+2348123456789',
            password: 'Admin123!',
            role: 'super_admin',
            is_email_verified: true,
            is_phone_verified: true,
            kyc_status: 'verified',
            balance: 1000000,
            referral_code: 'ADMIN001'
        });

        // Create investment plans
        const plans = [
            {
                name: 'Cocoa Beans',
                description: 'Invest in premium cocoa beans with stable returns',
                min_amount: 3500,
                daily_interest: 2.5,
                total_interest: 75,
                duration: 30,
                risk_level: 'low',
                category: 'cocoa',
                is_popular: true,
                is_active: true,
                referral_commission: 15,
                platform_fee: 5
            },
            {
                name: 'Gold',
                description: 'Precious metal investment with high liquidity',
                min_amount: 50000,
                daily_interest: 3.2,
                total_interest: 96,
                duration: 30,
                risk_level: 'medium',
                category: 'gold',
                is_popular: true,
                is_active: true,
                referral_commission: 15,
                platform_fee: 5
            },
            {
                name: 'Crude Oil',
                description: 'Energy sector investment with premium returns',
                min_amount: 100000,
                daily_interest: 4.1,
                total_interest: 123,
                duration: 30,
                risk_level: 'high',
                category: 'oil',
                is_popular: false,
                is_active: true,
                referral_commission: 15,
                platform_fee: 5
            },
            {
                name: 'Agricultural Produce',
                description: 'Investment in various agricultural products',
                min_amount: 10000,
                daily_interest: 2.8,
                total_interest: 84,
                duration: 30,
                risk_level: 'medium',
                category: 'agriculture',
                is_popular: true,
                is_active: true,
                referral_commission: 15,
                platform_fee: 5
            },
            {
                name: 'Precious Metals',
                description: 'Diversified precious metals portfolio',
                min_amount: 75000,
                daily_interest: 3.5,
                total_interest: 105,
                duration: 30,
                risk_level: 'medium',
                category: 'precious_metals',
                is_popular: false,
                is_active: true,
                referral_commission: 15,
                platform_fee: 5
            }
        ];

        await InvestmentPlan.insertMany(plans);

        console.log('✅ Database seeded successfully');
        console.log(`👤 Admin created: admin@rawwealthy.com / Admin123!`);
        console.log(`📊 ${plans.length} investment plans created`);
        
        process.exit(0);
    } catch (error) {
        console.error('❌ Database seeding failed:', error);
        process.exit(1);
    }
}

seedDatabase();
