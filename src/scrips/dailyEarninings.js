const mongoose = require('mongoose');
const Investment = require('../models/Investment');
const User = require('../models/User');
const Transaction = require('../models/Transaction');
const Wallet = require('../models/Wallet');
const Notification = require('../models/Notification');
const { connectDB } = require('../config/database');
const winston = require('winston');

// Create logger
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({ filename: 'logs/daily-earnings.log' }),
    new winston.transports.Console()
  ]
});

async function processDailyEarnings() {
  try {
    logger.info('Starting daily earnings processing...');
    
    // Connect to database
    await connectDB();
    
    // Get all active investments
    const activeInvestments = await Investment.find({ 
      status: 'active',
      next_payout: { $lte: new Date() }
    }).populate('user').populate('plan');
    
    logger.info(`Found ${activeInvestments.length} investments to process`);
    
    let totalEarningsProcessed = 0;
    let totalUsersAffected = 0;
    const processedInvestments = [];
    const failedInvestments = [];
    
    // Process each investment
    for (const investment of activeInvestments) {
      try {
        // Calculate daily earnings
        const dailyEarnings = investment.processDailyEarnings();
        
        // Update user balance
        const user = investment.user;
        user.balance += dailyEarnings;
        user.total_earnings += dailyEarnings;
        await user.save();
        
        // Update wallet
        const wallet = await Wallet.findOne({ user: user._id });
        if (wallet) {
          wallet.balance += dailyEarnings;
          wallet.total_earnings += dailyEarnings;
          await wallet.save();
        }
        
        // Create transaction record
        await Transaction.create({
          user: user._id,
          type: 'earnings',
          amount: dailyEarnings,
          description: `Daily earnings from ${investment.plan.name} investment`,
          reference: `EARN-${Date.now()}-${Math.random().toString(36).substr(2, 9).toUpperCase()}`,
          status: 'completed',
          metadata: {
            investment_id: investment._id,
            plan_name: investment.plan.name,
            daily_interest: investment.daily_interest,
            investment_amount: investment.amount,
            payout_day: investment.payout_count
          }
        });
        
        // Check if investment is matured
        if (investment.isMatured()) {
          investment.status = 'completed';
          
          // Add final earnings
          const totalEarned = investment.total_earned;
          user.balance += investment.amount; // Return principal
          user.total_earnings += totalEarned - investment.total_earned; // Add any remaining earnings
          await user.save();
          
          // Update wallet
          if (wallet) {
            wallet.balance += investment.amount;
            wallet.total_earnings += totalEarned - investment.total_earned;
            await wallet.save();
          }
          
          // Create transaction for principal return
          await Transaction.create({
            user: user._id,
            type: 'principal_return',
            amount: investment.amount,
            description: `Principal return from ${investment.plan.name} investment`,
            reference: `PRIN-${Date.now()}-${Math.random().toString(36).substr(2, 9).toUpperCase()}`,
            status: 'completed',
            metadata: {
              investment_id: investment._id,
              plan_name: investment.plan.name,
              duration: investment.duration,
              total_earned: totalEarned
            }
          });
          
          // Send completion notification
          await Notification.create({
            user: user._id,
            title: 'Investment Completed',
            message: `Your investment in ${investment.plan.name} has completed. Principal and earnings have been credited to your account.`,
            type: 'success',
            data: {
              investment_id: investment._id,
              plan_name: investment.plan.name,
              amount: investment.amount,
              total_earned: totalEarned
            }
          });
          
          logger.info(`Investment ${investment._id} completed for user ${user.email}`);
        }
        
        // Save updated investment
        await investment.save();
        
        // Send daily earnings notification
        await Notification.create({
          user: user._id,
          title: 'Daily Earnings Credited',
          message: `₦${dailyEarnings.toLocaleString()} has been credited to your account from ${investment.plan.name} investment.`,
          type: 'info',
          data: {
            investment_id: investment._id,
            plan_name: investment.plan.name,
            daily_earnings: dailyEarnings,
            total_earned: investment.total_earned
          }
        });
        
        processedInvestments.push(investment._id);
        totalEarningsProcessed += dailyEarnings;
        totalUsersAffected++;
        
        logger.info(`Processed earnings for investment ${investment._id}: ₦${dailyEarnings}`);
        
      } catch (error) {
        logger.error(`Failed to process investment ${investment._id}:`, error);
        failedInvestments.push({
          investment_id: investment._id,
          error: error.message
        });
      }
    }
    
    // Process auto-renew investments
    const completedInvestments = await Investment.find({
      status: 'completed',
      auto_renew: true,
      renewed_at: { $exists: false }
    }).populate('user').populate('plan');
    
    logger.info(`Found ${completedInvestments.length} investments to auto-renew`);
    
    for (const investment of completedInvestments) {
      try {
        // Check if plan still exists and is active
        const plan = investment.plan;
        if (!plan || !plan.is_active || !plan.auto_renew_allowed) {
          investment.auto_renew = false;
          await investment.save();
          continue;
        }
        
        // Create new investment with same amount
        const newEndDate = new Date();
        newEndDate.setDate(newEndDate.getDate() + plan.duration);
        
        const newInvestment = await Investment.create({
          user: investment.user._id,
          plan: investment.plan._id,
          amount: investment.amount,
          currency: 'NGN',
          daily_interest: plan.daily_interest,
          total_interest: plan.total_interest,
          daily_earnings: plan.calculateDailyEarnings(investment.amount),
          expected_total: investment.amount + plan.calculateTotalEarnings(investment.amount),
          duration: plan.duration,
          end_date: newEndDate,
          auto_renew: true,
          status: 'active'
        });
        
        // Mark old investment as renewed
        investment.renewed_at = new Date();
        investment.renewed_investment = newInvestment._id;
        await investment.save();
        
        // Update plan statistics
        await require('../models/InvestmentPlan').updatePlanStats(investment.plan._id, investment.amount);
        
        // Send auto-renew notification
        await Notification.create({
          user: investment.user._id,
          title: 'Investment Auto-Renewed',
          message: `Your investment in ${plan.name} has been automatically renewed for another ${plan.duration} days.`,
          type: 'info',
          data: {
            old_investment_id: investment._id,
            new_investment_id: newInvestment._id,
            plan_name: plan.name,
            amount: investment.amount
          }
        });
        
        logger.info(`Auto-renewed investment ${investment._id} to ${newInvestment._id}`);
        
      } catch (error) {
        logger.error(`Failed to auto-renew investment ${investment._id}:`, error);
      }
    }
    
    // Send summary notification to admin
    await Notification.create({
      user: await User.findOne({ role: 'admin' }).select('_id'),
      title: 'Daily Earnings Processing Complete',
      message: `Processed ${processedInvestments.length} investments. Total earnings: ₦${totalEarningsProcessed.toLocaleString()}. Affected users: ${totalUsersAffected}. Failed: ${failedInvestments.length}.`,
      type: 'info',
      data: {
        processed_count: processedInvestments.length,
        total_earnings: totalEarningsProcessed,
        users_affected: totalUsersAffected,
        failed_count: failedInvestments.length,
        failed_investments: failedInvestments,
        timestamp: new Date().toISOString()
      }
    });
    
    logger.info(`Daily earnings processing completed:
      Processed: ${processedInvestments.length}
      Total Earnings: ₦${totalEarningsProcessed.toLocaleString()}
      Users Affected: ${totalUsersAffected}
      Failed: ${failedInvestments.length}`);
    
    // Disconnect from database
    await mongoose.connection.close();
    
  } catch (error) {
    logger.error('Daily earnings processing failed:', error);
    process.exit(1);
  }
}

// Run script if called directly
if (require.main === module) {
  processDailyEarnings()
    .then(() => {
      logger.info('Script execution completed');
      process.exit(0);
    })
    .catch((error) => {
      logger.error('Script execution failed:', error);
      process.exit(1);
    });
}

module.exports = { processDailyEarnings };
