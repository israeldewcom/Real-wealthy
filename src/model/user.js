const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');

const userSchema = new mongoose.Schema({
  // Personal Information
  full_name: {
    type: String,
    required: [true, 'Full name is required'],
    trim: true,
    minlength: [2, 'Full name must be at least 2 characters'],
    maxlength: [100, 'Full name cannot exceed 100 characters']
  },
  
  email: {
    type: String,
    required: [true, 'Email is required'],
    unique: true,
    lowercase: true,
    trim: true,
    validate: {
      validator: function(v) {
        return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v);
      },
      message: 'Please enter a valid email address'
    }
  },
  
  phone: {
    type: String,
    required: [true, 'Phone number is required'],
    unique: true,
    validate: {
      validator: function(v) {
        return /^[+]?[1-9]\d{1,14}$/.test(v);
      },
      message: 'Please enter a valid phone number'
    }
  },
  
  password: {
    type: String,
    required: [true, 'Password is required'],
    minlength: [6, 'Password must be at least 6 characters'],
    select: false
  },
  
  // Account Information
  role: {
    type: String,
    enum: ['user', 'admin', 'super_admin'],
    default: 'user'
  },
  
  is_active: {
    type: Boolean,
    default: true
  },
  
  is_email_verified: {
    type: Boolean,
    default: false
  },
  
  is_phone_verified: {
    type: Boolean,
    default: false
  },
  
  email_verification_token: String,
  email_verification_expires: Date,
  
  phone_verification_code: String,
  phone_verification_expires: Date,
  
  // Financial Information
  balance: {
    type: Number,
    default: 0,
    min: 0
  },
  
  total_earnings: {
    type: Number,
    default: 0,
    min: 0
  },
  
  total_invested: {
    type: Number,
    default: 0,
    min: 0
  },
  
  total_withdrawn: {
    type: Number,
    default: 0,
    min: 0
  },
  
  referral_earnings: {
    type: Number,
    default: 0,
    min: 0
  },
  
  // Referral System
  referral_code: {
    type: String,
    unique: true,
    uppercase: true
  },
  
  referred_by: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  },
  
  referral_count: {
    type: Number,
    default: 0
  },
  
  // Investment Preferences
  risk_tolerance: {
    type: String,
    enum: ['low', 'medium', 'high'],
    default: 'medium'
  },
  
  investment_strategy: {
    type: String,
    enum: ['conservative', 'balanced', 'aggressive'],
    default: 'balanced'
  },
  
  // KYC Information
  kyc_status: {
    type: String,
    enum: ['pending', 'verified', 'rejected', 'not_submitted'],
    default: 'not_submitted'
  },
  
  kyc_documents: {
    id_type: String,
    id_number: String,
    id_front_url: String,
    id_back_url: String,
    selfie_with_id_url: String,
    address_proof_url: String,
    verified_at: Date,
    verified_by: mongoose.Schema.Types.ObjectId
  },
  
  // Bank Details
  bank_details: {
    bank_name: String,
    account_name: String,
    account_number: String,
    bank_code: String,
    verified: {
      type: Boolean,
      default: false
    },
    verified_at: Date
  },
  
  // Wallet/Crypto Information
  wallet_address: String,
  wallet_network: String,
  
  // Two-Factor Authentication
  two_factor_enabled: {
    type: Boolean,
    default: false
  },
  
  two_factor_secret: String,
  two_factor_backup_codes: [String],
  
  // Security
  login_attempts: {
    type: Number,
    default: 0
  },
  
  lock_until: Date,
  
  password_reset_token: String,
  password_reset_expires: Date,
  
  last_login: Date,
  last_login_ip: String,
  last_login_device: String,
  
  // Account Preferences
  preferences: {
    currency: {
      type: String,
      default: 'NGN'
    },
    language: {
      type: String,
      default: 'en'
    },
    timezone: {
      type: String,
      default: 'Africa/Lagos'
    },
    email_notifications: {
      type: Boolean,
      default: true
    },
    sms_notifications: {
      type: Boolean,
      default: true
    },
    push_notifications: {
      type: Boolean,
      default: true
    },
    marketing_emails: {
      type: Boolean,
      default: true
    }
  },
  
  // Metadata
  ip_address: String,
  user_agent: String,
  country: String,
  
  // Timestamps
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
userSchema.virtual('active_investments', {
  ref: 'Investment',
  localField: '_id',
  foreignField: 'user',
  match: { status: 'active' }
});

userSchema.virtual('total_referrals', {
  ref: 'User',
  localField: '_id',
  foreignField: 'referred_by',
  count: true
});

// Indexes
userSchema.index({ email: 1 });
userSchema.index({ phone: 1 });
userSchema.index({ referral_code: 1 });
userSchema.index({ created_at: -1 });
userSchema.index({ balance: -1 });
userSchema.index({ 'kyc_status': 1 });
userSchema.index({ role: 1, is_active: 1 });

// Middleware
userSchema.pre('save', async function(next) {
  // Update timestamp
  this.updated_at = Date.now();
  
  // Hash password if modified
  if (this.isModified('password')) {
    this.password = await bcrypt.hash(this.password, 12);
  }
  
  // Generate referral code if new user
  if (this.isNew && !this.referral_code) {
    this.referral_code = this.generateReferralCode();
  }
  
  next();
});

// Methods
userSchema.methods.generateReferralCode = function() {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  let code = '';
  for (let i = 0; i < 8; i++) {
    code += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return code;
};

userSchema.methods.comparePassword = async function(candidatePassword) {
  return await bcrypt.compare(candidatePassword, this.password);
};

userSchema.methods.createPasswordResetToken = function() {
  const resetToken = crypto.randomBytes(32).toString('hex');
  
  this.password_reset_token = crypto
    .createHash('sha256')
    .update(resetToken)
    .digest('hex');
    
  this.password_reset_expires = Date.now() + 10 * 60 * 1000; // 10 minutes
  
  return resetToken;
};

userSchema.methods.createEmailVerificationToken = function() {
  const verificationToken = crypto.randomBytes(32).toString('hex');
  
  this.email_verification_token = crypto
    .createHash('sha256')
    .update(verificationToken)
    .digest('hex');
    
  this.email_verification_expires = Date.now() + 24 * 60 * 60 * 1000; // 24 hours
  
  return verificationToken;
};

userSchema.methods.generate2FASecret = function() {
  const secret = crypto.randomBytes(20).toString('hex');
  this.two_factor_secret = secret;
  
  // Generate backup codes
  const backupCodes = [];
  for (let i = 0; i < 10; i++) {
    backupCodes.push(crypto.randomBytes(4).toString('hex').toUpperCase());
  }
  this.two_factor_backup_codes = backupCodes;
  
  return { secret, backupCodes };
};

userSchema.methods.incrementLoginAttempts = function() {
  if (this.lock_until && this.lock_until > Date.now()) {
    return false; // Account is still locked
  }
  
  this.login_attempts += 1;
  
  if (this.login_attempts >= 5) {
    // Lock account for 30 minutes
    this.lock_until = Date.now() + 30 * 60 * 1000;
    this.login_attempts = 0;
  }
  
  return true;
};

userSchema.methods.resetLoginAttempts = function() {
  this.login_attempts = 0;
  this.lock_until = undefined;
};

// Static Methods
userSchema.statics.findByEmail = function(email) {
  return this.findOne({ email }).select('+password');
};

userSchema.statics.findByPhone = function(phone) {
  return this.findOne({ phone }).select('+password');
};

userSchema.statics.findByReferralCode = function(referralCode) {
  return this.findOne({ referral_code: referralCode.toUpperCase() });
};

userSchema.statics.getUserStats = async function() {
  const stats = await this.aggregate([
    {
      $group: {
        _id: null,
        total_users: { $sum: 1 },
        active_users: { $sum: { $cond: [{ $eq: ['$is_active', true] }, 1, 0] } },
        verified_users: { $sum: { $cond: [{ $eq: ['$kyc_status', 'verified'] }, 1, 0] } },
        total_balance: { $sum: '$balance' },
        total_earnings: { $sum: '$total_earnings' },
        avg_balance: { $avg: '$balance' }
      }
    }
  ]);
  
  return stats[0] || {
    total_users: 0,
    active_users: 0,
    verified_users: 0,
    total_balance: 0,
    total_earnings: 0,
    avg_balance: 0
  };
};

const User = mongoose.model('User', userSchema);

module.exports = User;
