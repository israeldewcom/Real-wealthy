const mongoose = require('mongoose');

const investmentSchema = new mongoose.Schema({
  // User Reference
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  
  // Plan Reference
  plan: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'InvestmentPlan',
    required: true
  },
  
  // Investment Details
  amount: {
    type: Number,
    required: [true, 'Investment amount is required'],
    min: [0, 'Amount cannot be negative']
  },
  
  currency: {
    type: String,
    default: 'NGN'
  },
  
  // Returns
  daily_interest: {
    type: Number,
    required: true
  },
  
  total_interest: {
    type: Number,
    required: true
  },
  
  daily_earnings: {
    type: Number,
    default: 0
  },
  
  total_earned: {
    type: Number,
    default: 0
  },
  
  expected_total: {
    type: Number,
    required: true
  },
  
  // Duration
  duration: {
    type: Number,
    required: true
  },
  
  start_date: {
    type: Date,
    default: Date.now
  },
  
  end_date: {
    type: Date,
    required: true
  },
  
  // Status
  status: {
    type: String,
    enum: ['pending', 'active', 'completed', 'cancelled', 'suspended'],
    default: 'pending'
  },
  
  // Auto Renew
  auto_renew: {
    type: Boolean,
    default: false
  },
  
  // Payment Proof
  payment_proof_url: String,
  payment_proof_verified: {
    type: Boolean,
    default: false
  },
  
  // Payout Schedule
  last_payout: Date,
  next_payout: Date,
  
  payout_count: {
    type: Number,
    default: 0
  },
  
  payout_days_completed: {
    type: Number,
    default: 0
  },
  
  // Early Withdrawal
  early_withdrawal_requested: {
    type: Boolean,
    default: false
  },
  
  early_withdrawal_penalty: {
    type: Number,
    default: 0
  },
  
  // Referral Commission
  referral_commission_paid: {
    type: Boolean,
    default: false
  },
  
  referral_commission_amount: {
    type: Number,
    default: 0
  },
  
  // Admin Actions
  approved_by: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  },
  
  approved_at: Date,
  
  rejected_by: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  },
  
  rejected_at: Date,
  
  rejection_reason: String,
  
  // Metadata
  ip_address: String,
  user_agent: String,
  
  created_at: {
    type: Date,
    default: Date.now
  },
  
  updated_at: {
    type: Date,
    default: Date.now
  }
}, {
  timestamps: { createdAt: 'created_at', updatedAt: 'updated_at' },
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

// Virtuals
investmentSchema.virtual('remaining_days').get(function() {
  if (this.status !== 'active') return 0;
  const now = new Date();
  const end = new Date(this.end_date);
  const diff = Math.max(0, Math.ceil((end - now) / (1000 * 60 * 60 * 24)));
  return diff;
});

investmentSchema.virtual('days_elapsed').get(function() {
  const now = new Date();
  const start = new Date(this.start_date);
  const diff = Math.floor((now - start) / (1000 * 60 * 60 * 24));
  return Math.min(diff, this.duration);
});

investmentSchema.virtual('progress_percentage').get(function() {
  if (this.status !== 'active') return 0;
  const elapsed = this.days_elapsed;
  return Math.min(100, (elapsed / this.duration) * 100);
});

investmentSchema.virtual('expected_daily_earnings').get(function() {
  return (this.amount * this.daily_interest) / 100;
});

// Indexes
investmentSchema.index({ user: 1, status: 1 });
investmentSchema.index({ status: 1 });
investmentSchema.index({ end_date: 1 });
investmentSchema.index({ created_at: -1 });
investmentSchema.index({ plan: 1 });

// Middleware
investmentSchema.pre('save', function(next) {
  this.updated_at = Date.now();
  
  // Calculate expected total if not set
  if (!this.expected_total) {
    this.expected_total = this.amount + ((this.amount * this.total_interest) / 100);
  }
  
  // Calculate end date if not set
  if (!this.end_date && this.start_date && this.duration) {
    const endDate = new Date(this.start_date);
    endDate.setDate(endDate.getDate() + this.duration);
    this.end_date = endDate;
  }
  
  next();
});

// Methods
investmentSchema.methods.calculateDailyEarnings = function() {
  return (this.amount * this.daily_interest) / 100;
};

investmentSchema.methods.calculateTotalEarnings = function() {
  const daysElapsed = this.days_elapsed;
  const dailyEarnings = this.calculateDailyEarnings();
  return daysElapsed * dailyEarnings;
};

investmentSchema.methods.processDailyEarnings = function() {
  const dailyEarnings = this.calculateDailyEarnings();
  
  this.total_earned += dailyEarnings;
  this.payout_days_completed += 1;
  this.last_payout = new Date();
  
  // Set next payout to tomorrow
  const nextPayout = new Date();
  nextPayout.setDate(nextPayout.getDate() + 1);
  nextPayout.setHours(0, 0, 0, 0);
  this.next_payout = nextPayout;
  
  this.payout_count += 1;
  
  return dailyEarnings;
};

investmentSchema.methods.isMatured = function() {
  return this.days_elapsed >= this.duration;
};

investmentSchema.methods.canWithdrawEarly = function() {
  return this.early_withdrawal_requested && this.early_withdrawal_penalty > 0;
};

investmentSchema.methods.calculateEarlyWithdrawal = function() {
  const penaltyAmount = (this.amount * this.early_withdrawal_penalty) / 100;
  const withdrawalAmount = this.amount + this.total_earned - penaltyAmount;
  
  return {
    principal: this.amount,
    earnings: this.total_earned,
    penalty: penaltyAmount,
    total: withdrawalAmount
  };
};

// Static Methods
investmentSchema.statics.getActiveInvestments = function(userId) {
  return this.find({ user: userId, status: 'active' })
    .populate('plan', 'name daily_interest total_interest duration')
    .sort({ created_at: -1 });
};

investmentSchema.statics.getPendingInvestments = function() {
  return this.find({ status: 'pending' })
    .populate('user', 'full_name email phone')
    .populate('plan', 'name min_amount')
    .sort({ created_at: -1 });
};

investmentSchema.statics.getMaturedInvestments = function() {
  const now = new Date();
  return this.find({ 
    status: 'active',
    end_date: { $lte: now }
  });
};

investmentSchema.statics.getInvestmentStats = async function(userId) {
  const stats = await this.aggregate([
    { $match: { user: mongoose.Types.ObjectId(userId) } },
    {
      $group: {
        _id: null,
        total_invested: { $sum: '$amount' },
        total_earned: { $sum: '$total_earned' },
        active_investments: { 
          $sum: { $cond: [{ $eq: ['$status', 'active'] }, 1, 0] }
        },
        completed_investments: { 
          $sum: { $cond: [{ $eq: ['$status', 'completed'] }, 1, 0] }
        },
        active_investment_value: {
          $sum: { $cond: [{ $eq: ['$status', 'active'] }, '$amount', 0] }
        }
      }
    }
  ]);
  
  return stats[0] || {
    total_invested: 0,
    total_earned: 0,
    active_investments: 0,
    completed_investments: 0,
    active_investment_value: 0
  };
};

investmentSchema.statics.getPlatformInvestmentStats = async function() {
  const stats = await this.aggregate([
    {
      $group: {
        _id: null,
        total_investments: { $sum: 1 },
        total_amount_invested: { $sum: '$amount' },
        total_earnings_paid: { $sum: '$total_earned' },
        pending_investments: { 
          $sum: { $cond: [{ $eq: ['$status', 'pending'] }, 1, 0] }
        },
        active_investments: { 
          $sum: { $cond: [{ $eq: ['$status', 'active'] }, 1, 0] }
        },
        completed_investments: { 
          $sum: { $cond: [{ $eq: ['$status', 'completed'] }, 1, 0] }
        }
      }
    }
  ]);
  
  return stats[0] || {
    total_investments: 0,
    total_amount_invested: 0,
    total_earnings_paid: 0,
    pending_investments: 0,
    active_investments: 0,
    completed_investments: 0
  };
};

const Investment = mongoose.model('Investment', investmentSchema);

module.exports = Investment;
