const User = require('../models/User');
const Investment = require('../models/Investment');
const Deposit = require('../models/Deposit');
const Withdrawal = require('../models/Withdrawal');
const Transaction = require('../models/Transaction');
const KYC = require('../models/KYC');
const SupportTicket = require('../models/SupportTicket');
const Referral = require('../models/Referral');
const Notification = require('../models/Notification');
const AdminLog = require('../models/AdminLog');
const { sendAdminNotification } = require('../services/notificationService');

// @desc    Get admin dashboard statistics
// @route   GET /api/admin/dashboard
// @access  Private/Admin
exports.getDashboardStats = async (req, res) => {
  try {
    // Get user statistics
    const userStats = await User.getUserStats();
    
    // Get investment statistics
    const investmentStats = await Investment.getPlatformInvestmentStats();
    
    // Get deposit statistics
    const depositStats = await Deposit.aggregate([
      {
        $group: {
          _id: null,
          total_deposits: { $sum: 1 },
          total_deposit_amount: { $sum: '$amount' },
          pending_deposits: { 
            $sum: { $cond: [{ $eq: ['$status', 'pending'] }, 1, 0] }
          },
          completed_deposits: { 
            $sum: { $cond: [{ $eq: ['$status', 'completed'] }, 1, 0] }
          }
        }
      }
    ]);
    
    // Get withdrawal statistics
    const withdrawalStats = await Withdrawal.aggregate([
      {
        $group: {
          _id: null,
          total_withdrawals: { $sum: 1 },
          total_withdrawal_amount: { $sum: '$amount' },
          pending_withdrawals: { 
            $sum: { $cond: [{ $eq: ['$status', 'pending'] }, 1, 0] }
          },
          completed_withdrawals: { 
            $sum: { $cond: [{ $eq: ['$status', 'completed'] }, 1, 0] }
          },
          total_platform_fees: { $sum: '$platform_fee' }
        }
      }
    ]);
    
    // Get KYC statistics
    const kycStats = await KYC.aggregate([
      {
        $group: {
          _id: null,
          total_kyc: { $sum: 1 },
          pending_kyc: { 
            $sum: { $cond: [{ $eq: ['$status', 'pending'] }, 1, 0] }
          },
          approved_kyc: { 
            $sum: { $cond: [{ $eq: ['$status', 'approved'] }, 1, 0] }
          },
          rejected_kyc: { 
            $sum: { $cond: [{ $eq: ['$status', 'rejected'] }, 1, 0] }
          }
        }
      }
    ]);
    
    // Get recent activities
    const recentActivities = await AdminLog.find()
      .populate('admin', 'full_name email')
      .sort({ created_at: -1 })
      .limit(10);
    
    // Get daily stats for the last 7 days
    const sevenDaysAgo = new Date();
    sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);
    
    const dailyStats = await Transaction.aggregate([
      {
        $match: {
          created_at: { $gte: sevenDaysAgo }
        }
      },
      {
        $group: {
          _id: { $dateToString: { format: '%Y-%m-%d', date: '$created_at' } },
          deposits: { 
            $sum: { $cond: [{ $eq: ['$type', 'deposit'] }, '$amount', 0] }
          },
          withdrawals: { 
            $sum: { $cond: [{ $eq: ['$type', 'withdrawal'] }, '$amount', 0] }
          },
          investments: { 
            $sum: { $cond: [{ $eq: ['$type', 'investment'] }, '$amount', 0] }
          }
        }
      },
      { $sort: { '_id': 1 } }
    ]);
    
    // Calculate platform earnings
    const platformEarnings = withdrawalStats[0]?.total_platform_fees || 0;
    
    // Calculate pending actions
    const pendingActions = 
      (depositStats[0]?.pending_deposits || 0) +
      (withdrawalStats[0]?.pending_withdrawals || 0) +
      (kycStats[0]?.pending_kyc || 0);
    
    const stats = {
      users: userStats,
      investments: investmentStats,
      deposits: depositStats[0] || {},
      withdrawals: withdrawalStats[0] || {},
      kyc: kycStats[0] || {},
      platform_earnings: platformEarnings,
      pending_actions: pendingActions,
      recent_activities: recentActivities,
      daily_stats: dailyStats
    };
    
    // Log admin action
    await AdminLog.create({
      admin: req.user.id,
      action: 'view_dashboard',
      details: 'Viewed admin dashboard statistics',
      ip_address: req.ip,
      user_agent: req.headers['user-agent']
    });
    
    res.status(200).json({
      success: true,
      data: { stats }
    });
  } catch (error) {
    console.error('Get dashboard stats error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch dashboard statistics'
    });
  }
};

// @desc    Get all users
// @route   GET /api/admin/users
// @access  Private/Admin
exports.getUsers = async (req, res) => {
  try {
    const { 
      page = 1, 
      limit = 20, 
      search, 
      role, 
      kyc_status,
      is_active,
      sort = '-created_at' 
    } = req.query;
    
    // Build query
    const query = {};
    
    if (search) {
      query.$or = [
        { full_name: { $regex: search, $options: 'i' } },
        { email: { $regex: search, $options: 'i' } },
        { phone: { $regex: search, $options: 'i' } },
        { referral_code: { $regex: search, $options: 'i' } }
      ];
    }
    
    if (role) query.role = role;
    if (kyc_status) query.kyc_status = kyc_status;
    if (is_active !== undefined) query.is_active = is_active === 'true';
    
    // Pagination
    const pageInt = parseInt(page, 10);
    const limitInt = parseInt(limit, 10);
    const skip = (pageInt - 1) * limitInt;
    
    // Execute query
    const users = await User.find(query)
      .select('-password -email_verification_token -phone_verification_code')
      .sort(sort)
      .skip(skip)
      .limit(limitInt);
    
    // Get total count
    const total = await User.countDocuments(query);
    
    // Log admin action
    await AdminLog.create({
      admin: req.user.id,
      action: 'view_users',
      details: `Viewed users list (Page: ${page}, Search: ${search || 'none'})`,
      ip_address: req.ip,
      user_agent: req.headers['user-agent']
    });
    
    res.status(200).json({
      success: true,
      data: {
        users,
        pagination: {
          page: pageInt,
          limit: limitInt,
          total,
          pages: Math.ceil(total / limitInt)
        }
      }
    });
  } catch (error) {
    console.error('Get users error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch users'
    });
  }
};

// @desc    Get single user details
// @route   GET /api/admin/users/:id
// @access  Private/Admin
exports.getUser = async (req, res) => {
  try {
    const user = await User.findById(req.params.id)
      .select('-password -email_verification_token -phone_verification_code')
      .populate('referred_by', 'full_name email referral_code');
    
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }
    
    // Get user's investments
    const investments = await Investment.find({ user: user._id })
      .populate('plan', 'name')
      .sort({ created_at: -1 })
      .limit(10);
    
    // Get user's transactions
    const transactions = await Transaction.find({ user: user._id })
      .sort({ created_at: -1 })
      .limit(10);
    
    // Get user's referrals
    const referrals = await Referral.find({ referrer: user._id })
      .populate('referred_user', 'full_name email created_at')
      .sort({ created_at: -1 })
      .limit(10);
    
    // Get user's support tickets
    const supportTickets = await SupportTicket.find({ user: user._id })
      .sort({ created_at: -1 })
      .limit(5);
    
    const userData = {
      ...user.toObject(),
      investments,
      transactions,
      referrals,
      supportTickets
    };
    
    // Log admin action
    await AdminLog.create({
      admin: req.user.id,
      action: 'view_user',
      details: `Viewed user details: ${user.full_name} (${user.email})`,
      ip_address: req.ip,
      user_agent: req.headers['user-agent'],
      target_user: user._id
    });
    
    res.status(200).json({
      success: true,
      data: { user: userData }
    });
  } catch (error) {
    console.error('Get user error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch user details'
    });
  }
};

// @desc    Update user
// @route   PUT /api/admin/users/:id
// @access  Private/Admin
exports.updateUser = async (req, res) => {
  try {
    const { 
      full_name, 
      email, 
      phone, 
      role, 
      is_active, 
      kyc_status,
      balance,
      total_earnings,
      referral_earnings
    } = req.body;
    
    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }
    
    // Check if email already exists (if changing email)
    if (email && email !== user.email) {
      const existingUser = await User.findOne({ email });
      if (existingUser) {
        return res.status(400).json({
          success: false,
          message: 'Email already exists'
        });
      }
    }
    
    // Check if phone already exists (if changing phone)
    if (phone && phone !== user.phone) {
      const existingUser = await User.findOne({ phone });
      if (existingUser) {
        return res.status(400).json({
          success: false,
          message: 'Phone number already exists'
        });
      }
    }
    
    // Update user fields
    const updateFields = {};
    if (full_name) updateFields.full_name = full_name;
    if (email) updateFields.email = email.toLowerCase();
    if (phone) updateFields.phone = phone;
    if (role) updateFields.role = role;
    if (is_active !== undefined) updateFields.is_active = is_active;
    if (kyc_status) updateFields.kyc_status = kyc_status;
    if (balance !== undefined) updateFields.balance = parseFloat(balance);
    if (total_earnings !== undefined) updateFields.total_earnings = parseFloat(total_earnings);
    if (referral_earnings !== undefined) updateFields.referral_earnings = parseFloat(referral_earnings);
    
    const updatedUser = await User.findByIdAndUpdate(
      req.params.id,
      updateFields,
      { new: true, runValidators: true }
    ).select('-password');
    
    // Create transaction if balance was adjusted
    if (balance !== undefined && balance !== user.balance) {
      const difference = parseFloat(balance) - user.balance;
      if (difference !== 0) {
        await Transaction.create({
          user: user._id,
          type: difference > 0 ? 'admin_credit' : 'admin_debit',
          amount: difference,
          description: `Admin adjustment: ${difference > 0 ? 'Credit' : 'Debit'}`,
          reference: `ADJ-${Date.now()}-${Math.random().toString(36).substr(2, 9).toUpperCase()}`,
          status: 'completed',
          metadata: {
            admin_id: req.user.id,
            previous_balance: user.balance,
            new_balance: balance,
            reason: req.body.adjustment_reason || 'Admin adjustment'
          }
        });
        
        // Update wallet if exists
        const Wallet = require('../models/Wallet');
        const wallet = await Wallet.findOne({ user: user._id });
        if (wallet) {
          wallet.balance = parseFloat(balance);
          await wallet.save();
        }
      }
    }
    
    // Log admin action
    await AdminLog.create({
      admin: req.user.id,
      action: 'update_user',
      details: `Updated user: ${user.full_name} (${user.email})`,
      ip_address: req.ip,
      user_agent: req.headers['user-agent'],
      target_user: user._id,
      changes: updateFields
    });
    
    // Send notification to user if status changed
    if (is_active !== undefined && is_active !== user.is_active) {
      await sendAdminNotification(
        user._id,
        is_active ? 'account_activated' : 'account_suspended',
        {
          reason: req.body.suspension_reason || 'Account status changed by admin'
        }
      );
    }
    
    res.status(200).json({
      success: true,
      message: 'User updated successfully',
      data: { user: updatedUser }
    });
  } catch (error) {
    console.error('Update user error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to update user'
    });
  }
};

// @desc    Adjust user balance
// @route   POST /api/admin/users/:id/adjust-balance
// @access  Private/Admin
exports.adjustUserBalance = async (req, res) => {
  try {
    const { amount, type, description } = req.body;
    
    if (!amount || !type || !description) {
      return res.status(400).json({
        success: false,
        message: 'Amount, type, and description are required'
      });
    }
    
    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }
    
    const adjustmentAmount = parseFloat(amount);
    if (isNaN(adjustmentAmount) || adjustmentAmount <= 0) {
      return res.status(400).json({
        success: false,
        message: 'Invalid amount'
      });
    }
    
    const finalAmount = type === 'add' ? adjustmentAmount : -adjustmentAmount;
    const newBalance = user.balance + finalAmount;
    
    if (newBalance < 0) {
      return res.status(400).json({
        success: false,
        message: 'Insufficient balance after adjustment'
      });
    }
    
    // Update user balance
    user.balance = newBalance;
    await user.save();
    
    // Update wallet
    const Wallet = require('../models/Wallet');
    const wallet = await Wallet.findOne({ user: user._id });
    if (wallet) {
      wallet.balance = newBalance;
      await wallet.save();
    }
    
    // Create transaction
    const transaction = await Transaction.create({
      user: user._id,
      type: type === 'add' ? 'admin_credit' : 'admin_debit',
      amount: finalAmount,
      description: description,
      reference: `ADJ-${Date.now()}-${Math.random().toString(36).substr(2, 9).toUpperCase()}`,
      status: 'completed',
      metadata: {
        admin_id: req.user.id,
        adjustment_type: type,
        previous_balance: user.balance - finalAmount,
        new_balance: newBalance
      }
    });
    
    // Log admin action
    await AdminLog.create({
      admin: req.user.id,
      action: 'adjust_balance',
      details: `Adjusted balance for ${user.full_name}: ${type} ${adjustmentAmount}`,
      ip_address: req.ip,
      user_agent: req.headers['user-agent'],
      target_user: user._id,
      changes: {
        adjustment_type: type,
        amount: adjustmentAmount,
        description: description,
        transaction_id: transaction._id
      }
    });
    
    // Send notification to user
    await sendAdminNotification(
      user._id,
      'balance_adjusted',
      {
        amount: finalAmount,
        type: type,
        description: description,
        new_balance: newBalance
      }
    );
    
    res.status(200).json({
      success: true,
      message: `Balance ${type === 'add' ? 'added' : 'deducted'} successfully`,
      data: {
        user: {
          _id: user._id,
          full_name: user.full_name,
          previous_balance: user.balance - finalAmount,
          new_balance: user.balance
        },
        transaction
      }
    });
  } catch (error) {
    console.error('Adjust balance error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to adjust balance'
    });
  }
};

// @desc    Get pending investments
// @route   GET /api/admin/pending-investments
// @access  Private/Admin
exports.getPendingInvestments = async (req, res) => {
  try {
    const { page = 1, limit = 20 } = req.query;
    
    const pageInt = parseInt(page, 10);
    const limitInt = parseInt(limit, 10);
    const skip = (pageInt - 1) * limitInt;
    
    const investments = await Investment.find({ status: 'pending' })
      .populate('user', 'full_name email phone')
      .populate('plan', 'name min_amount daily_interest')
      .sort({ created_at: -1 })
      .skip(skip)
      .limit(limitInt);
    
    const total = await Investment.countDocuments({ status: 'pending' });
    
    res.status(200).json({
      success: true,
      data: {
        investments,
        pagination: {
          page: pageInt,
          limit: limitInt,
          total,
          pages: Math.ceil(total / limitInt)
        }
      }
    });
  } catch (error) {
    console.error('Get pending investments error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch pending investments'
    });
  }
};

// @desc    Approve investment
// @route   POST /api/admin/investments/:id/approve
// @access  Private/Admin
exports.approveInvestment = async (req, res) => {
  try {
    const investment = await Investment.findById(req.params.id)
      .populate('user')
      .populate('plan');
    
    if (!investment) {
      return res.status(404).json({
        success: false,
        message: 'Investment not found'
      });
    }
    
    if (investment.status !== 'pending') {
      return res.status(400).json({
        success: false,
        message: 'Investment is not pending approval'
      });
    }
    
    // Update investment status
    investment.status = 'active';
    investment.approved_by = req.user.id;
    investment.approved_at = new Date();
    investment.payment_proof_verified = true;
    
    // Set next payout date
    const nextPayout = new Date();
    nextPayout.setDate(nextPayout.getDate() + 1);
    nextPayout.setHours(0, 0, 0, 0);
    investment.next_payout = nextPayout;
    
    await investment.save();
    
    // Update user's total invested
    await User.findByIdAndUpdate(investment.user._id, {
      $inc: { total_invested: investment.amount }
    });
    
    // Log admin action
    await AdminLog.create({
      admin: req.user.id,
      action: 'approve_investment',
      details: `Approved investment: ${investment.plan.name} for ${investment.user.full_name}`,
      ip_address: req.ip,
      user_agent: req.headers['user-agent'],
      target_user: investment.user._id,
      changes: {
        investment_id: investment._id,
        amount: investment.amount,
        plan: investment.plan.name
      }
    });
    
    // Send notification to user
    await sendAdminNotification(
      investment.user._id,
      'investment_approved',
      {
        plan_name: investment.plan.name,
        amount: investment.amount,
        investment_id: investment._id
      }
    );
    
    res.status(200).json({
      success: true,
      message: 'Investment approved successfully',
      data: { investment }
    });
  } catch (error) {
    console.error('Approve investment error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to approve investment'
    });
  }
};

// @desc    Reject investment
// @route   POST /api/admin/investments/:id/reject
// @access  Private/Admin
exports.rejectInvestment = async (req, res) => {
  try {
    const { remarks } = req.body;
    
    if (!remarks) {
      return res.status(400).json({
        success: false,
        message: 'Rejection remarks are required'
      });
    }
    
    const investment = await Investment.findById(req.params.id)
      .populate('user')
      .populate('plan');
    
    if (!investment) {
      return res.status(404).json({
        success: false,
        message: 'Investment not found'
      });
    }
    
    if (investment.status !== 'pending') {
      return res.status(400).json({
        success: false,
        message: 'Investment is not pending approval'
      });
    }
    
    // Update investment status
    investment.status = 'cancelled';
    investment.rejected_by = req.user.id;
    investment.rejected_at = new Date();
    investment.rejection_reason = remarks;
    
    await investment.save();
    
    // Refund amount to user's wallet
    const user = await User.findById(investment.user._id);
    if (user) {
      user.balance += investment.amount;
      await user.save();
      
      // Update wallet
      const Wallet = require('../models/Wallet');
      const wallet = await Wallet.findOne({ user: investment.user._id });
      if (wallet) {
        wallet.balance += investment.amount;
        await wallet.save();
      }
      
      // Create transaction for refund
      await Transaction.create({
        user: investment.user._id,
        type: 'refund',
        amount: investment.amount,
        description: `Refund for rejected investment in ${investment.plan.name}`,
        reference: `REF-${Date.now()}-${Math.random().toString(36).substr(2, 9).toUpperCase()}`,
        status: 'completed',
        metadata: {
          investment_id: investment._id,
          plan_name: investment.plan.name,
          rejection_reason: remarks
        }
      });
    }
    
    // Log admin action
    await AdminLog.create({
      admin: req.user.id,
      action: 'reject_investment',
      details: `Rejected investment: ${investment.plan.name} for ${investment.user.full_name}`,
      ip_address: req.ip,
      user_agent: req.headers['user-agent'],
      target_user: investment.user._id,
      changes: {
        investment_id: investment._id,
        amount: investment.amount,
        plan: investment.plan.name,
        remarks: remarks
      }
    });
    
    // Send notification to user
    await sendAdminNotification(
      investment.user._id,
      'investment_rejected',
      {
        plan_name: investment.plan.name,
        amount: investment.amount,
        investment_id: investment._id,
        reason: remarks
      }
    );
    
    res.status(200).json({
      success: true,
      message: 'Investment rejected successfully',
      data: { investment }
    });
  } catch (error) {
    console.error('Reject investment error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to reject investment'
    });
  }
};

// @desc    Get pending deposits
// @route   GET /api/admin/pending-deposits
// @access  Private/Admin
exports.getPendingDeposits = async (req, res) => {
  try {
    const deposits = await Deposit.find({ status: 'pending' })
      .populate('user', 'full_name email phone')
      .sort({ created_at: -1 })
      .limit(50);
    
    res.status(200).json({
      success: true,
      count: deposits.length,
      data: { deposits }
    });
  } catch (error) {
    console.error('Get pending deposits error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch pending deposits'
    });
  }
};

// @desc    Approve deposit
// @route   POST /api/admin/deposits/:id/approve
// @access  Private/Admin
exports.approveDeposit = async (req, res) => {
  try {
    const deposit = await Deposit.findById(req.params.id)
      .populate('user');
    
    if (!deposit) {
      return res.status(404).json({
        success: false,
        message: 'Deposit not found'
      });
    }
    
    if (deposit.status !== 'pending') {
      return res.status(400).json({
        success: false,
        message: 'Deposit is not pending approval'
      });
    }
    
    // Update deposit status
    deposit.status = 'completed';
    deposit.processed_by = req.user.id;
    deposit.processed_at = new Date();
    await deposit.save();
    
    // Update user balance
    const user = await User.findById(deposit.user._id);
    if (user) {
      user.balance += deposit.amount;
      await user.save();
      
      // Update wallet
      const Wallet = require('../models/Wallet');
      const wallet = await Wallet.findOne({ user: deposit.user._id });
      if (wallet) {
        wallet.balance += deposit.amount;
        wallet.total_deposits += deposit.amount;
        await wallet.save();
      }
      
      // Update transaction status
      await Transaction.findByIdAndUpdate(deposit.transaction, {
        status: 'completed',
        balance_after: user.balance
      });
    }
    
    // Log admin action
    await AdminLog.create({
      admin: req.user.id,
      action: 'approve_deposit',
      details: `Approved deposit of ${deposit.amount} for ${deposit.user.full_name}`,
      ip_address: req.ip,
      user_agent: req.headers['user-agent'],
      target_user: deposit.user._id,
      changes: {
        deposit_id: deposit._id,
        amount: deposit.amount,
        payment_method: deposit.payment_method
      }
    });
    
    // Send notification to user
    await sendAdminNotification(
      deposit.user._id,
      'deposit_approved',
      {
        amount: deposit.amount,
        deposit_id: deposit._id,
        payment_method: deposit.payment_method
      }
    );
    
    res.status(200).json({
      success: true,
      message: 'Deposit approved successfully',
      data: { deposit }
    });
  } catch (error) {
    console.error('Approve deposit error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to approve deposit'
    });
  }
};

// @desc    Reject deposit
// @route   POST /api/admin/deposits/:id/reject
// @access  Private/Admin
exports.rejectDeposit = async (req, res) => {
  try {
    const { remarks } = req.body;
    
    if (!remarks) {
      return res.status(400).json({
        success: false,
        message: 'Rejection remarks are required'
      });
    }
    
    const deposit = await Deposit.findById(req.params.id)
      .populate('user');
    
    if (!deposit) {
      return res.status(404).json({
        success: false,
        message: 'Deposit not found'
      });
    }
    
    if (deposit.status !== 'pending') {
      return res.status(400).json({
        success: false,
        message: 'Deposit is not pending approval'
      });
    }
    
    // Update deposit status
    deposit.status = 'rejected';
    deposit.processed_by = req.user.id;
    deposit.processed_at = new Date();
    deposit.remarks = remarks;
    await deposit.save();
    
    // Update transaction status
    await Transaction.findByIdAndUpdate(deposit.transaction, {
      status: 'failed',
      remarks: `Deposit rejected: ${remarks}`
    });
    
    // Log admin action
    await AdminLog.create({
      admin: req.user.id,
      action: 'reject_deposit',
      details: `Rejected deposit of ${deposit.amount} for ${deposit.user.full_name}`,
      ip_address: req.ip,
      user_agent: req.headers['user-agent'],
      target_user: deposit.user._id,
      changes: {
        deposit_id: deposit._id,
        amount: deposit.amount,
        payment_method: deposit.payment_method,
        remarks: remarks
      }
    });
    
    // Send notification to user
    await sendAdminNotification(
      deposit.user._id,
      'deposit_rejected',
      {
        amount: deposit.amount,
        deposit_id: deposit._id,
        payment_method: deposit.payment_method,
        reason: remarks
      }
    );
    
    res.status(200).json({
      success: true,
      message: 'Deposit rejected successfully',
      data: { deposit }
    });
  } catch (error) {
    console.error('Reject deposit error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to reject deposit'
    });
  }
};

// @desc    Get pending withdrawals
// @route   GET /api/admin/pending-withdrawals
// @access  Private/Admin
exports.getPendingWithdrawals = async (req, res) => {
  try {
    const withdrawals = await Withdrawal.find({ status: 'pending' })
      .populate('user', 'full_name email phone bank_details')
      .sort({ created_at: -1 })
      .limit(50);
    
    res.status(200).json({
      success: true,
      count: withdrawals.length,
      data: { withdrawals }
    });
  } catch (error) {
    console.error('Get pending withdrawals error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch pending withdrawals'
    });
  }
};

// @desc    Approve withdrawal
// @route   POST /api/admin/withdrawals/:id/approve
// @access  Private/Admin
exports.approveWithdrawal = async (req, res) => {
  try {
    const { transaction_id } = req.body;
    
    const withdrawal = await Withdrawal.findById(req.params.id)
      .populate('user');
    
    if (!withdrawal) {
      return res.status(404).json({
        success: false,
        message: 'Withdrawal not found'
      });
    }
    
    if (withdrawal.status !== 'pending') {
      return res.status(400).json({
        success: false,
        message: 'Withdrawal is not pending approval'
      });
    }
    
    // Update withdrawal status
    withdrawal.status = 'completed';
    withdrawal.processed_by = req.user.id;
    withdrawal.processed_at = new Date();
    withdrawal.transaction_id = transaction_id;
    await withdrawal.save();
    
    // Update user's total withdrawn
    const user = await User.findById(withdrawal.user._id);
    if (user) {
      user.total_withdrawn += withdrawal.amount;
      await user.save();
      
      // Update wallet
      const Wallet = require('../models/Wallet');
      const wallet = await Wallet.findOne({ user: withdrawal.user._id });
      if (wallet) {
        wallet.total_withdrawals += withdrawal.amount;
        await wallet.save();
      }
      
      // Update transaction status
      await Transaction.findByIdAndUpdate(withdrawal.transaction, {
        status: 'completed',
        metadata: {
          ...withdrawal.transaction?.metadata,
          admin_approved: true,
          admin_id: req.user.id,
          external_transaction_id: transaction_id
        }
      });
    }
    
    // Log admin action
    await AdminLog.create({
      admin: req.user.id,
      action: 'approve_withdrawal',
      details: `Approved withdrawal of ${withdrawal.amount} for ${withdrawal.user.full_name}`,
      ip_address: req.ip,
      user_agent: req.headers['user-agent'],
      target_user: withdrawal.user._id,
      changes: {
        withdrawal_id: withdrawal._id,
        amount: withdrawal.amount,
        net_amount: withdrawal.net_amount,
        platform_fee: withdrawal.platform_fee,
        payment_method: withdrawal.payment_method,
        transaction_id: transaction_id
      }
    });
    
    // Send notification to user
    await sendAdminNotification(
      withdrawal.user._id,
      'withdrawal_approved',
      {
        amount: withdrawal.amount,
        net_amount: withdrawal.net_amount,
        withdrawal_id: withdrawal._id,
        payment_method: withdrawal.payment_method,
        transaction_id: transaction_id
      }
    );
    
    res.status(200).json({
      success: true,
      message: 'Withdrawal approved successfully',
      data: { withdrawal }
    });
  } catch (error) {
    console.error('Approve withdrawal error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to approve withdrawal'
    });
  }
};

// @desc    Reject withdrawal
// @route   POST /api/admin/withdrawals/:id/reject
// @access  Private/Admin
exports.rejectWithdrawal = async (req, res) => {
  try {
    const { remarks } = req.body;
    
    if (!remarks) {
      return res.status(400).json({
        success: false,
        message: 'Rejection remarks are required'
      });
    }
    
    const withdrawal = await Withdrawal.findById(req.params.id)
      .populate('user');
    
    if (!withdrawal) {
      return res.status(404).json({
        success: false,
        message: 'Withdrawal not found'
      });
    }
    
    if (withdrawal.status !== 'pending') {
      return res.status(400).json({
        success: false,
        message: 'Withdrawal is not pending approval'
      });
    }
    
    // Update withdrawal status
    withdrawal.status = 'rejected';
    withdrawal.processed_by = req.user.id;
    withdrawal.processed_at = new Date();
    withdrawal.remarks = remarks;
    await withdrawal.save();
    
    // Refund amount to user's wallet (including platform fee)
    const user = await User.findById(withdrawal.user._id);
    if (user) {
      user.balance += withdrawal.amount;
      await user.save();
      
      // Update wallet
      const Wallet = require('../models/Wallet');
      const wallet = await Wallet.findOne({ user: withdrawal.user._id });
      if (wallet) {
        wallet.balance += withdrawal.amount;
        await wallet.save();
      }
      
      // Update transaction status
      await Transaction.findByIdAndUpdate(withdrawal.transaction, {
        status: 'failed',
        remarks: `Withdrawal rejected: ${remarks}`
      });
    }
    
    // Log admin action
    await AdminLog.create({
      admin: req.user.id,
      action: 'reject_withdrawal',
      details: `Rejected withdrawal of ${withdrawal.amount} for ${withdrawal.user.full_name}`,
      ip_address: req.ip,
      user_agent: req.headers['user-agent'],
      target_user: withdrawal.user._id,
      changes: {
        withdrawal_id: withdrawal._id,
        amount: withdrawal.amount,
        payment_method: withdrawal.payment_method,
        remarks: remarks
      }
    });
    
    // Send notification to user
    await sendAdminNotification(
      withdrawal.user._id,
      'withdrawal_rejected',
      {
        amount: withdrawal.amount,
        withdrawal_id: withdrawal._id,
        payment_method: withdrawal.payment_method,
        reason: remarks
      }
    );
    
    res.status(200).json({
      success: true,
      message: 'Withdrawal rejected successfully',
      data: { withdrawal }
    });
  } catch (error) {
    console.error('Reject withdrawal error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to reject withdrawal'
    });
  }
};

// @desc    Get pending KYC applications
// @route   GET /api/admin/pending-kyc
// @access  Private/Admin
exports.getPendingKYC = async (req, res) => {
  try {
    const kycApplications = await KYC.find({ status: 'pending' })
      .populate('user', 'full_name email phone')
      .sort({ created_at: -1 })
      .limit(50);
    
    res.status(200).json({
      success: true,
      count: kycApplications.length,
      data: { kyc_applications: kycApplications }
    });
  } catch (error) {
    console.error('Get pending KYC error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch pending KYC applications'
    });
  }
};

// @desc    Approve KYC
// @route   POST /api/admin/kyc/:id/approve
// @access  Private/Admin
exports.approveKYC = async (req, res) => {
  try {
    const kyc = await KYC.findById(req.params.id)
      .populate('user');
    
    if (!kyc) {
      return res.status(404).json({
        success: false,
        message: 'KYC application not found'
      });
    }
    
    if (kyc.status !== 'pending') {
      return res.status(400).json({
        success: false,
        message: 'KYC application is not pending approval'
      });
    }
    
    // Update KYC status
    kyc.status = 'approved';
    kyc.reviewed_by = req.user.id;
    kyc.reviewed_at = new Date();
    await kyc.save();
    
    // Update user KYC status
    const user = await User.findById(kyc.user._id);
    if (user) {
      user.kyc_status = 'verified';
      user.kyc_documents = {
        id_type: kyc.id_type,
        id_number: kyc.id_number,
        id_front_url: kyc.id_front_url,
        id_back_url: kyc.id_back_url,
        selfie_with_id_url: kyc.selfie_with_id_url,
        address_proof_url: kyc.address_proof_url,
        verified_at: new Date(),
        verified_by: req.user.id
      };
      await user.save();
    }
    
    // Log admin action
    await AdminLog.create({
      admin: req.user.id,
      action: 'approve_kyc',
      details: `Approved KYC for ${kyc.user.full_name}`,
      ip_address: req.ip,
      user_agent: req.headers['user-agent'],
      target_user: kyc.user._id
    });
    
    // Send notification to user
    await sendAdminNotification(
      kyc.user._id,
      'kyc_approved',
      {
        user_name: kyc.user.full_name
      }
    );
    
    res.status(200).json({
      success: true,
      message: 'KYC approved successfully',
      data: { kyc }
    });
  } catch (error) {
    console.error('Approve KYC error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to approve KYC'
    });
  }
};

// @desc    Reject KYC
// @route   POST /api/admin/kyc/:id/reject
// @access  Private/Admin
exports.rejectKYC = async (req, res) => {
  try {
    const { rejection_reason } = req.body;
    
    if (!rejection_reason) {
      return res.status(400).json({
        success: false,
        message: 'Rejection reason is required'
      });
    }
    
    const kyc = await KYC.findById(req.params.id)
      .populate('user');
    
    if (!kyc) {
      return res.status(404).json({
        success: false,
        message: 'KYC application not found'
      });
    }
    
    if (kyc.status !== 'pending') {
      return res.status(400).json({
        success: false,
        message: 'KYC application is not pending approval'
      });
    }
    
    // Update KYC status
    kyc.status = 'rejected';
    kyc.reviewed_by = req.user.id;
    kyc.reviewed_at = new Date();
    kyc.rejection_reason = rejection_reason;
    await kyc.save();
    
    // Update user KYC status
    const user = await User.findById(kyc.user._id);
    if (user) {
      user.kyc_status = 'rejected';
      await user.save();
    }
    
    // Log admin action
    await AdminLog.create({
      admin: req.user.id,
      action: 'reject_kyc',
      details: `Rejected KYC for ${kyc.user.full_name}`,
      ip_address: req.ip,
      user_agent: req.headers['user-agent'],
      target_user: kyc.user._id,
      changes: {
        rejection_reason: rejection_reason
      }
    });
    
    // Send notification to user
    await sendAdminNotification(
      kyc.user._id,
      'kyc_rejected',
      {
        user_name: kyc.user.full_name,
        reason: rejection_reason
      }
    );
    
    res.status(200).json({
      success: true,
      message: 'KYC rejected successfully',
      data: { kyc }
    });
  } catch (error) {
    console.error('Reject KYC error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to reject KYC'
    });
  }
};

// @desc    Send notification to users
// @route   POST /api/admin/notifications/send
// @access  Private/Admin
exports.sendNotification = async (req, res) => {
  try {
    const { user_id, title, message, type = 'info' } = req.body;
    
    if (!title || !message) {
      return res.status(400).json({
        success: false,
        message: 'Title and message are required'
      });
    }
    
    let users = [];
    
    if (user_id) {
      // Send to specific user
      const user = await User.findById(user_id);
      if (!user) {
        return res.status(404).json({
          success: false,
          message: 'User not found'
        });
      }
      users = [user];
    } else {
      // Send to all active users
      users = await User.find({ is_active: true });
    }
    
    // Create notifications for each user
    const notificationPromises = users.map(user => 
      Notification.create({
        user: user._id,
        title,
        message,
        type,
        is_read: false
      })
    );
    
    await Promise.all(notificationPromises);
    
    // Log admin action
    await AdminLog.create({
      admin: req.user.id,
      action: 'send_notification',
      details: `Sent notification to ${users.length} users: ${title}`,
      ip_address: req.ip,
      user_agent: req.headers['user-agent'],
      changes: {
        title,
        message,
        type,
        user_count: users.length
      }
    });
    
    res.status(200).json({
      success: true,
      message: `Notification sent to ${users.length} users successfully`
    });
  } catch (error) {
    console.error('Send notification error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to send notification'
    });
  }
};

// @desc    Get admin logs
// @route   GET /api/admin/logs
// @access  Private/Admin
exports.getAdminLogs = async (req, res) => {
  try {
    const { page = 1, limit = 50, admin_id, action } = req.query;
    
    // Build query
    const query = {};
    if (admin_id) query.admin = admin_id;
    if (action) query.action = action;
    
    // Pagination
    const pageInt = parseInt(page, 10);
    const limitInt = parseInt(limit, 10);
    const skip = (pageInt - 1) * limitInt;
    
    const logs = await AdminLog.find(query)
      .populate('admin', 'full_name email')
      .populate('target_user', 'full_name email')
      .sort({ created_at: -1 })
      .skip(skip)
      .limit(limitInt);
    
    const total = await AdminLog.countDocuments(query);
    
    res.status(200).json({
      success: true,
      data: {
        logs,
        pagination: {
          page: pageInt,
          limit: limitInt,
          total,
          pages: Math.ceil(total / limitInt)
        }
      }
    });
  } catch (error) {
    console.error('Get admin logs error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch admin logs'
    });
  }
};
