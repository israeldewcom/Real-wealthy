const mongoose = require('mongoose');

const investmentPlanSchema = new mongoose.Schema({
  // Basic Information
  name: {
    type: String,
    required: [true, 'Plan name is required'],
    trim: true,
    unique: true
  },
  
  slug: {
    type: String,
    unique: true,
    lowercase: true
  },
  
  description: {
    type: String,
    required: [true, 'Plan description is required'],
    maxlength: [500, 'Description cannot exceed 500 characters']
  },
  
  // Investment Details
  min_amount: {
    type: Number,
    required: [true, 'Minimum investment amount is required'],
    min: [0, 'Minimum amount cannot be negative']
  },
  
  max_amount: {
    type: Number,
    default: null // null means no maximum
  },
  
  // Returns
  daily_interest: {
    type: Number,
    required: [true, 'Daily interest rate is required'],
    min: [0, 'Interest rate cannot be negative'],
    max: [100, 'Interest rate cannot exceed 100%']
  },
  
  total_interest: {
    type: Number,
    required: [true, 'Total interest rate is required'],
    min: [0, 'Total interest cannot be negative'],
    max: [1000, 'Total interest cannot exceed 1000%']
  },
  
  // Duration
  duration: {
    type: Number,
    required: [true, 'Investment duration is required'],
    min: [1, 'Duration must be at least 1 day']
  },
  
  duration_unit: {
    type: String,
    enum: ['days', 'months', 'years'],
    default: 'days'
  },
  
  // Risk and Category
  risk_level: {
    type: String,
    enum: ['low', 'medium', 'high'],
    default: 'medium'
  },
  
  category: {
    type: String,
    enum: ['cocoa', 'gold', 'oil', 'agriculture', 'mining', 'energy', 'precious_metals'],
    required: true
  },
  
  // Features
  is_active: {
    type: Boolean,
    default: true
  },
  
  is_popular: {
    type: Boolean,
    default: false
  },
  
  is_featured: {
    type: Boolean,
    default: false
  },
  
  // Commission Structure
  referral_commission: {
    type: Number,
    default: 15,
    min: 0,
    max: 100
  },
  
  platform_fee: {
    type: Number,
    default: 5,
    min: 0,
    max: 100
  },
  
  // Withdrawal Rules
  withdrawal_allowed: {
    type: Boolean,
    default: true
  },
  
  early_withdrawal_penalty: {
    type: Number,
    default: 0,
    min: 0,
    max: 100
  },
  
  // Auto Renew
  auto_renew_allowed: {
    type: Boolean,
    default: true
  },
  
  // Investment Statistics
  total_investors: {
    type: Number,
    default: 0
  },
  
  total_invested: {
    type: Number,
    default: 0
  },
  
  total_earnings: {
    type: Number,
    default: 0
  },
  
  // Visuals
  icon: String,
  color: String,
  image_url: String,
  
  // Terms and Conditions
  terms: [String],
  
  // Metadata
  created_by: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  },
  
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
investmentPlanSchema.virtual('total_days').get(function() {
  if (this.duration_unit === 'days') return this.duration;
  if (this.duration_unit === 'months') return this.duration * 30;
  if (this.duration_unit === 'years') return this.duration * 365;
  return this.duration;
});

investmentPlanSchema.virtual('daily_return_percentage').get(function() {
  return this.daily_interest;
});

investmentPlanSchema.virtual('total_return_percentage').get(function() {
  return this.total_interest;
});

// Middleware
investmentPlanSchema.pre('save', function(next) {
  // Generate slug from name
  if (this.isModified('name')) {
    this.slug = this.name
      .toLowerCase()
      .replace(/[^\w\s]/gi, '')
      .replace(/\s+/g, '-');
  }
  
  this.updated_at = Date.now();
  next();
});

// Methods
investmentPlanSchema.methods.calculateDailyEarnings = function(investmentAmount) {
  return (investmentAmount * this.daily_interest) / 100;
};

investmentPlanSchema.methods.calculateTotalEarnings = function(investmentAmount) {
  return (investmentAmount * this.total_interest) / 100;
};

investmentPlanSchema.methods.calculatePlatformFee = function(amount) {
  return (amount * this.platform_fee) / 100;
};

// Static Methods
investmentPlanSchema.statics.getActivePlans = function() {
  return this.find({ is_active: true }).sort({ min_amount: 1 });
};

investmentPlanSchema.statics.getPopularPlans = function() {
  return this.find({ is_active: true, is_popular: true }).limit(3);
};

investmentPlanSchema.statics.getPlanStats = async function() {
  const stats = await this.aggregate([
    {
      $group: {
        _id: null,
        total_plans: { $sum: 1 },
        active_plans: { $sum: { $cond: [{ $eq: ['$is_active', true] }, 1, 0] } },
        total_invested: { $sum: '$total_invested' },
        avg_daily_interest: { $avg: '$daily_interest' },
        plan_categories: { $addToSet: '$category' }
      }
    }
  ]);
  
  return stats[0] || {
    total_plans: 0,
    active_plans: 0,
    total_invested: 0,
    avg_daily_interest: 0,
    plan_categories: []
  };
};

investmentPlanSchema.statics.updatePlanStats = async function(planId, amount) {
  await this.findByIdAndUpdate(planId, {
    $inc: {
      total_investors: 1,
      total_invested: amount
    }
  });
};

const InvestmentPlan = mongoose.model('InvestmentPlan', investmentPlanSchema);

module.exports = InvestmentPlan;
