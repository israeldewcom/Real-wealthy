const Investment = require('../models/Investment');
const InvestmentPlan = require('../models/InvestmentPlan');
const User = require('../models/User');
const Transaction = require('../models/Transaction');
const Referral = require('../models/Referral');
const Wallet = require('../models/Wallet');
const { processReferralBonus } = require('../services/referralService');
const { createInvestmentNotification } = require('../services/notificationService');
const { uploadFile } = require('../services/fileUploadService');

// @desc    Get all investment plans
// @route   GET /api/investments/plans
// @access  Public
exports.getInvestmentPlans = async (req, res) => {
  try {
    const plans = await InvestmentPlan.find({ is_active: true })
      .sort({ min_amount: 1 });

    res.status(200).json({
      success: true,
      count: plans.length,
      data: { plans }
    });
  } catch (error) {
    console.error('Get investment plans error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch investment plans'
    });
  }
};

// @desc    Get popular investment plans
// @route   GET /api/investments/plans/popular
// @access  Public
exports.getPopularPlans = async (req, res) => {
  try {
    const plans = await InvestmentPlan.getPopularPlans();

    res.status(200).json({
      success: true,
      data: { plans }
    });
  } catch (error) {
    console.error('Get popular plans error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch popular plans'
    });
  }
};

// @desc    Get single investment plan
// @route   GET /api/investments/plans/:id
// @access  Public
exports.getInvestmentPlan = async (req, res) => {
  try {
    const plan = await InvestmentPlan.findById(req.params.id);

    if (!plan) {
      return res.status(404).json({
        success: false,
        message: 'Investment plan not found'
      });
    }

    res.status(200).json({
      success: true,
      data: { plan }
    });
  } catch (error) {
    console.error('Get investment plan error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch investment plan'
    });
  }
};

// @desc    Create new investment
// @route   POST /api/investments
// @access  Private
exports.createInvestment = async (req, res) => {
  try {
    const { plan_id, amount, auto_renew } = req.body;
    const userId = req.user.id;

    // Get user
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    // Check KYC status
    if (user.kyc_status !== 'verified') {
      return res.status(403).json({
        success: false,
        message: 'Please complete KYC verification before investing'
      });
    }

    // Get investment plan
    const plan = await InvestmentPlan.findById(plan_id);
    if (!plan || !plan.is_active) {
      return res.status(404).json({
        success: false,
        message: 'Investment plan not available'
      });
    }

    // Validate amount
    if (amount < plan.min_amount) {
      return res.status(400).json({
        success: false,
        message: `Minimum investment for ${plan.name} is ₦${plan.min_amount.toLocaleString()}`
      });
    }

    if (plan.max_amount && amount > plan.max_amount) {
      return res.status(400).json({
        success: false,
        message: `Maximum investment for ${plan.name} is ₦${plan.max_amount.toLocaleString()}`
      });
    }

    // Check if user has sufficient balance
    const wallet = await Wallet.findOne({ user: userId });
    if (!wallet || wallet.balance < amount) {
      return res.status(400).json({
        success: false,
        message: 'Insufficient balance'
      });
    }

    // Handle file upload
    let paymentProofUrl = null;
    if (req.file) {
      const uploadResult = await uploadFile(req.file, 'payment-proofs');
      paymentProofUrl = uploadResult.url;
    }

    // Calculate end date
    const endDate = new Date();
    endDate.setDate(endDate.getDate() + plan.duration);

    // Calculate expected returns
    const dailyEarnings = plan.calculateDailyEarnings(amount);
    const totalEarnings = plan.calculateTotalEarnings(amount);
    const expectedTotal = amount + totalEarnings;

    // Create investment
    const investment = await Investment.create({
      user: userId,
      plan: plan_id,
      amount,
      currency: 'NGN',
      daily_interest: plan.daily_interest,
      total_interest: plan.total_interest,
      daily_earnings: dailyEarnings,
      expected_total: expectedTotal,
      duration: plan.duration,
      end_date: endDate,
      auto_renew: auto_renew || false,
      payment_proof_url: paymentProofUrl,
      status: 'pending',
      ip_address: req.ip,
      user_agent: req.headers['user-agent']
    });

    // Deduct amount from wallet
    wallet.balance -= amount;
    wallet.total_invested += amount;
    await wallet.save();

    // Update user's total invested
    user.total_invested += amount;
    await user.save();

    // Update plan statistics
    await InvestmentPlan.updatePlanStats(plan_id, amount);

    // Create transaction record
    await Transaction.create({
      user: userId,
      type: 'investment',
      amount: -amount,
      description: `Investment in ${plan.name} Plan`,
      reference: `INV-${Date.now()}-${Math.random().toString(36).substr(2, 9).toUpperCase()}`,
      status: 'completed',
      metadata: {
        investment_id: investment._id,
        plan_name: plan.name,
        duration: plan.duration
      }
    });

    // Send notification
    await createInvestmentNotification(userId, 'pending', {
      plan_name: plan.name,
      amount: amount,
      investment_id: investment._id
    });

    // Process referral bonus if applicable
    if (user.referred_by) {
      await processReferralBonus(user.referred_by, userId, amount, plan.referral_commission);
    }

    res.status(201).json({
      success: true,
      message: 'Investment created successfully. Awaiting approval.',
      data: { investment }
    });
  } catch (error) {
    console.error('Create investment error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to create investment'
    });
  }
};

// @desc    Get user investments
// @route   GET /api/investments
// @access  Private
exports.getUserInvestments = async (req, res) => {
  try {
    const { status, page = 1, limit = 10, sort = '-created_at' } = req.query;
    const userId = req.user.id;

    // Build query
    const query = { user: userId };
    if (status) {
      query.status = status;
    }

    // Pagination
    const pageInt = parseInt(page, 10);
    const limitInt = parseInt(limit, 10);
    const skip = (pageInt - 1) * limitInt;

    // Execute query
    const investments = await Investment.find(query)
      .populate('plan', 'name daily_interest total_interest duration')
      .sort(sort)
      .skip(skip)
      .limit(limitInt);

    // Get total count
    const total = await Investment.countDocuments(query);

    // Get investment stats
    const stats = await Investment.getInvestmentStats(userId);

    res.status(200).json({
      success: true,
      data: {
        investments,
        pagination: {
          page: pageInt,
          limit: limitInt,
          total,
          pages: Math.ceil(total / limitInt)
        },
        stats
      }
    });
  } catch (error) {
    console.error('Get user investments error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch investments'
    });
  }
};

// @desc    Get single investment
// @route   GET /api/investments/:id
// @access  Private
exports.getInvestment = async (req, res) => {
  try {
    const investment = await Investment.findById(req.params.id)
      .populate('plan')
      .populate('user', 'full_name email phone');

    if (!investment) {
      return res.status(404).json({
        success: false,
        message: 'Investment not found'
      });
    }

    // Check if user owns the investment or is admin
    if (investment.user._id.toString() !== req.user.id && req.user.role === 'user') {
      return res.status(403).json({
        success: false,
        message: 'Not authorized to view this investment'
      });
    }

    res.status(200).json({
      success: true,
      data: { investment }
    });
  } catch (error) {
    console.error('Get investment error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch investment'
    });
  }
};

// @desc    Renew investment
// @route   POST /api/investments/:id/renew
// @access  Private
exports.renewInvestment = async (req, res) => {
  try {
    const investment = await Investment.findById(req.params.id);

    if (!investment) {
      return res.status(404).json({
        success: false,
        message: 'Investment not found'
      });
    }

    // Check if user owns the investment
    if (investment.user.toString() !== req.user.id) {
      return res.status(403).json({
        success: false,
        message: 'Not authorized'
      });
    }

    // Check if investment is completed
    if (investment.status !== 'completed') {
      return res.status(400).json({
        success: false,
        message: 'Only completed investments can be renewed'
      });
    }

    // Get plan
    const plan = await InvestmentPlan.findById(investment.plan);
    if (!plan || !plan.is_active) {
      return res.status(400).json({
        success: false,
        message: 'Investment plan no longer available'
      });
    }

    // Check if auto renew is allowed
    if (!plan.auto_renew_allowed) {
      return res.status(400).json({
        success: false,
        message: 'Auto renew is not allowed for this plan'
      });
    }

    // Create new investment with same amount
    const newEndDate = new Date();
    newEndDate.setDate(newEndDate.getDate() + plan.duration);

    const newInvestment = await Investment.create({
      user: req.user.id,
      plan: investment.plan,
      amount: investment.amount,
      currency: 'NGN',
      daily_interest: plan.daily_interest,
      total_interest: plan.total_interest,
      daily_earnings: plan.calculateDailyEarnings(investment.amount),
      expected_total: investment.amount + plan.calculateTotalEarnings(investment.amount),
      duration: plan.duration,
      end_date: newEndDate,
      auto_renew: investment.auto_renew,
      status: 'active'
    });

    // Update plan statistics
    await InvestmentPlan.updatePlanStats(investment.plan, investment.amount);

    // Create transaction
    await Transaction.create({
      user: req.user.id,
      type: 'investment_renewal',
      amount: 0,
      description: `Renewal of ${plan.name} Investment`,
      reference: `REN-${Date.now()}-${Math.random().toString(36).substr(2, 9).toUpperCase()}`,
      status: 'completed',
      metadata: {
        old_investment_id: investment._id,
        new_investment_id: newInvestment._id,
        plan_name: plan.name
      }
    });

    // Send notification
    await createInvestmentNotification(req.user.id, 'renewed', {
      plan_name: plan.name,
      amount: investment.amount,
      investment_id: newInvestment._id
    });

    res.status(200).json({
      success: true,
      message: 'Investment renewed successfully',
      data: { investment: newInvestment }
    });
  } catch (error) {
    console.error('Renew investment error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to renew investment'
    });
  }
};

// @desc    Request early withdrawal
// @route   POST /api/investments/:id/early-withdrawal
// @access  Private
exports.requestEarlyWithdrawal = async (req, res) => {
  try {
    const investment = await Investment.findById(req.params.id)
      .populate('plan');

    if (!investment) {
      return res.status(404).json({
        success: false,
        message: 'Investment not found'
      });
    }

    // Check if user owns the investment
    if (investment.user.toString() !== req.user.id) {
      return res.status(403).json({
        success: false,
        message: 'Not authorized'
      });
    }

    // Check if investment is active
    if (investment.status !== 'active') {
      return res.status(400).json({
        success: false,
        message: 'Only active investments can be withdrawn early'
      });
    }

    // Check if early withdrawal is allowed
    if (!investment.plan.withdrawal_allowed) {
      return res.status(400).json({
        success: false,
        message: 'Early withdrawal is not allowed for this plan'
      });
    }

    // Calculate early withdrawal amount
    const withdrawalDetails = investment.calculateEarlyWithdrawal();
    
    investment.early_withdrawal_requested = true;
    investment.status = 'pending_withdrawal';
    await investment.save();

    // Create withdrawal request
    const Withdrawal = require('../models/Withdrawal');
    const withdrawal = await Withdrawal.create({
      user: req.user.id,
      amount: withdrawalDetails.total,
      investment: investment._id,
      type: 'early_withdrawal',
      status: 'pending',
      metadata: {
        principal: withdrawalDetails.principal,
        earnings: withdrawalDetails.earnings,
        penalty: withdrawalDetails.penalty,
        net_amount: withdrawalDetails.total
      }
    });

    res.status(200).json({
      success: true,
      message: 'Early withdrawal request submitted',
      data: {
        withdrawal,
        details: withdrawalDetails
      }
    });
  } catch (error) {
    console.error('Early withdrawal error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to process early withdrawal request'
    });
  }
};

// @desc    Get investment statistics
// @route   GET /api/investments/stats
// @access  Private
exports.getInvestmentStats = async (req, res) => {
  try {
    const userId = req.user.id;

    const stats = await Investment.getInvestmentStats(userId);

    res.status(200).json({
      success: true,
      data: { stats }
    });
  } catch (error) {
    console.error('Get investment stats error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch investment statistics'
    });
  }
};
