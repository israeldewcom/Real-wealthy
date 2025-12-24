const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const Referral = require('../models/Referral');
const Wallet = require('../models/Wallet');
const { sendWelcomeEmail } = require('../services/emailService');
const { sendVerificationSMS } = require('../services/smsService');
const { generateToken, verifyToken } = require('../utils/security');
const { validateRegistration, validateLogin } = require('../utils/validators');

// @desc    Register user
// @route   POST /api/auth/register
// @access  Public
exports.register = async (req, res) => {
  try {
    // Validate input
    const { error } = validateRegistration(req.body);
    if (error) {
      return res.status(400).json({
        success: false,
        message: error.details[0].message
      });
    }

    const { full_name, email, phone, password, referral_code, risk_tolerance, investment_strategy } = req.body;

    // Check if user already exists
    const existingUser = await User.findOne({ $or: [{ email }, { phone }] });
    if (existingUser) {
      return res.status(400).json({
        success: false,
        message: 'User with this email or phone already exists'
      });
    }

    // Check referral code if provided
    let referredBy = null;
    if (referral_code) {
      const referrer = await User.findOne({ referral_code: referral_code.toUpperCase() });
      if (!referrer) {
        return res.status(400).json({
          success: false,
          message: 'Invalid referral code'
        });
      }
      referredBy = referrer._id;
    }

    // Create user
    const user = await User.create({
      full_name,
      email: email.toLowerCase(),
      phone,
      password,
      referred_by: referredBy,
      risk_tolerance: risk_tolerance || 'medium',
      investment_strategy: investment_strategy || 'balanced',
      ip_address: req.ip,
      user_agent: req.headers['user-agent'],
      country: req.headers['cf-ipcountry'] || 'NG'
    });

    // Create wallet for user
    await Wallet.create({
      user: user._id,
      balance: 0,
      currency: 'NGN'
    });

    // Handle referral if exists
    if (referredBy) {
      await Referral.create({
        referrer: referredBy,
        referred_user: user._id,
        status: 'pending',
        commission_rate: 15 // Default 15%
      });

      // Update referrer's count
      await User.findByIdAndUpdate(referredBy, {
        $inc: { referral_count: 1 }
      });
    }

    // Generate email verification token
    const verificationToken = user.createEmailVerificationToken();
    await user.save();

    // Generate phone verification code
    const verificationCode = Math.floor(100000 + Math.random() * 900000).toString();
    user.phone_verification_code = verificationCode;
    user.phone_verification_expires = Date.now() + 10 * 60 * 1000; // 10 minutes
    await user.save();

    // Generate JWT token
    const token = generateToken(user._id);

    // Remove sensitive data
    user.password = undefined;
    user.email_verification_token = undefined;
    user.phone_verification_code = undefined;

    // Send welcome email
    await sendWelcomeEmail(user.email, user.full_name, verificationToken);

    // Send verification SMS
    await sendVerificationSMS(user.phone, verificationCode);

    // Set cookie
    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
    });

    res.status(201).json({
      success: true,
      message: 'Registration successful! Please verify your email and phone.',
      data: {
        token,
        user: {
          _id: user._id,
          full_name: user.full_name,
          email: user.email,
          phone: user.phone,
          role: user.role,
          balance: user.balance,
          referral_code: user.referral_code,
          kyc_status: user.kyc_status,
          created_at: user.created_at
        }
      }
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({
      success: false,
      message: 'Registration failed. Please try again.'
    });
  }
};

// @desc    Login user
// @route   POST /api/auth/login
// @access  Public
exports.login = async (req, res) => {
  try {
    // Validate input
    const { error } = validateLogin(req.body);
    if (error) {
      return res.status(400).json({
        success: false,
        message: error.details[0].message
      });
    }

    const { email, password } = req.body;

    // Find user
    const user = await User.findOne({ email: email.toLowerCase() }).select('+password +login_attempts +lock_until');
    
    if (!user) {
      return res.status(401).json({
        success: false,
        message: 'Invalid credentials'
      });
    }

    // Check if account is locked
    if (user.lock_until && user.lock_until > Date.now()) {
      const lockTime = Math.ceil((user.lock_until - Date.now()) / 1000 / 60);
      return res.status(423).json({
        success: false,
        message: `Account is locked. Try again in ${lockTime} minutes.`
      });
    }

    // Check password
    const isPasswordValid = await user.comparePassword(password);
    if (!isPasswordValid) {
      // Increment login attempts
      user.incrementLoginAttempts();
      await user.save();

      return res.status(401).json({
        success: false,
        message: 'Invalid credentials'
      });
    }

    // Reset login attempts on successful login
    user.resetLoginAttempts();
    user.last_login = Date.now();
    user.last_login_ip = req.ip;
    user.last_login_device = req.headers['user-agent'];
    await user.save();

    // Generate JWT token
    const token = generateToken(user._id);

    // Remove sensitive data
    user.password = undefined;
    user.login_attempts = undefined;
    user.lock_until = undefined;

    // Set cookie
    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
    });

    res.status(200).json({
      success: true,
      message: 'Login successful',
      data: {
        token,
        user: {
          _id: user._id,
          full_name: user.full_name,
          email: user.email,
          phone: user.phone,
          role: user.role,
          balance: user.balance,
          kyc_status: user.kyc_status,
          is_email_verified: user.is_email_verified,
          is_phone_verified: user.is_phone_verified,
          two_factor_enabled: user.two_factor_enabled
        }
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({
      success: false,
      message: 'Login failed. Please try again.'
    });
  }
};

// @desc    Verify email
// @route   GET /api/auth/verify-email/:token
// @access  Public
exports.verifyEmail = async (req, res) => {
  try {
    const { token } = req.params;

    // Hash the token
    const hashedToken = crypto
      .createHash('sha256')
      .update(token)
      .digest('hex');

    // Find user with matching token and valid expiration
    const user = await User.findOne({
      email_verification_token: hashedToken,
      email_verification_expires: { $gt: Date.now() }
    });

    if (!user) {
      return res.status(400).json({
        success: false,
        message: 'Invalid or expired verification token'
      });
    }

    // Update user
    user.is_email_verified = true;
    user.email_verification_token = undefined;
    user.email_verification_expires = undefined;
    await user.save();

    res.status(200).json({
      success: true,
      message: 'Email verified successfully'
    });
  } catch (error) {
    console.error('Email verification error:', error);
    res.status(500).json({
      success: false,
      message: 'Email verification failed'
    });
  }
};

// @desc    Verify phone
// @route   POST /api/auth/verify-phone
// @access  Public
exports.verifyPhone = async (req, res) => {
  try {
    const { phone, code } = req.body;

    const user = await User.findOne({
      phone,
      phone_verification_code: code,
      phone_verification_expires: { $gt: Date.now() }
    });

    if (!user) {
      return res.status(400).json({
        success: false,
        message: 'Invalid or expired verification code'
      });
    }

    user.is_phone_verified = true;
    user.phone_verification_code = undefined;
    user.phone_verification_expires = undefined;
    await user.save();

    res.status(200).json({
      success: true,
      message: 'Phone verified successfully'
    });
  } catch (error) {
    console.error('Phone verification error:', error);
    res.status(500).json({
      success: false,
      message: 'Phone verification failed'
    });
  }
};

// @desc    Resend verification
// @route   POST /api/auth/resend-verification
// @access  Public
exports.resendVerification = async (req, res) => {
  try {
    const { email } = req.body;

    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    if (user.is_email_verified) {
      return res.status(400).json({
        success: false,
        message: 'Email already verified'
      });
    }

    // Generate new verification token
    const verificationToken = user.createEmailVerificationToken();
    await user.save();

    // Resend email
    await sendWelcomeEmail(user.email, user.full_name, verificationToken);

    res.status(200).json({
      success: true,
      message: 'Verification email sent successfully'
    });
  } catch (error) {
    console.error('Resend verification error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to resend verification email'
    });
  }
};

// @desc    Forgot password
// @route   POST /api/auth/forgot-password
// @access  Public
exports.forgotPassword = async (req, res) => {
  try {
    const { email } = req.body;

    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    // Generate reset token
    const resetToken = user.createPasswordResetToken();
    await user.save();

    // Send reset email
    const resetUrl = `${process.env.FRONTEND_URL}/reset-password/${resetToken}`;
    
    // In production, you would send an email here
    console.log('Password reset URL:', resetUrl);

    res.status(200).json({
      success: true,
      message: 'Password reset instructions sent to your email',
      data: {
        resetToken: process.env.NODE_ENV === 'development' ? resetToken : undefined
      }
    });
  } catch (error) {
    console.error('Forgot password error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to process password reset request'
    });
  }
};

// @desc    Reset password
// @route   POST /api/auth/reset-password/:token
// @access  Public
exports.resetPassword = async (req, res) => {
  try {
    const { token } = req.params;
    const { password } = req.body;

    // Hash the token
    const hashedToken = crypto
      .createHash('sha256')
      .update(token)
      .digest('hex');

    // Find user with matching token and valid expiration
    const user = await User.findOne({
      password_reset_token: hashedToken,
      password_reset_expires: { $gt: Date.now() }
    }).select('+password');

    if (!user) {
      return res.status(400).json({
        success: false,
        message: 'Invalid or expired reset token'
      });
    }

    // Update password
    user.password = password;
    user.password_reset_token = undefined;
    user.password_reset_expires = undefined;
    user.resetLoginAttempts();
    await user.save();

    // Generate new token
    const newToken = generateToken(user._id);

    res.status(200).json({
      success: true,
      message: 'Password reset successfully',
      data: {
        token: newToken
      }
    });
  } catch (error) {
    console.error('Reset password error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to reset password'
    });
  }
};

// @desc    Change password
// @route   POST /api/auth/change-password
// @access  Private
exports.changePassword = async (req, res) => {
  try {
    const { current_password, new_password } = req.body;
    const user = await User.findById(req.user.id).select('+password');

    // Verify current password
    const isPasswordValid = await user.comparePassword(current_password);
    if (!isPasswordValid) {
      return res.status(401).json({
        success: false,
        message: 'Current password is incorrect'
      });
    }

    // Update password
    user.password = new_password;
    await user.save();

    res.status(200).json({
      success: true,
      message: 'Password changed successfully'
    });
  } catch (error) {
    console.error('Change password error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to change password'
    });
  }
};

// @desc    Enable 2FA
// @route   POST /api/auth/enable-2fa
// @access  Private
exports.enable2FA = async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    
    if (user.two_factor_enabled) {
      return res.status(400).json({
        success: false,
        message: '2FA is already enabled'
      });
    }

    // Generate 2FA secret
    const { secret, backupCodes } = user.generate2FASecret();
    await user.save();

    // In production, use a 2FA library like speakeasy
    // For now, we'll return the secret for demo purposes
    res.status(200).json({
      success: true,
      message: '2FA enabled successfully',
      data: {
        secret: process.env.NODE_ENV === 'development' ? secret : undefined,
        backupCodes: process.env.NODE_ENV === 'development' ? backupCodes : undefined,
        qrCodeUrl: `otpauth://totp/RawWealthy:${user.email}?secret=${secret}&issuer=RawWealthy`
      }
    });
  } catch (error) {
    console.error('Enable 2FA error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to enable 2FA'
    });
  }
};

// @desc    Verify 2FA
// @route   POST /api/auth/verify-2fa
// @access  Private
exports.verify2FA = async (req, res) => {
  try {
    const { token } = req.body;
    const user = await User.findById(req.user.id);

    // In production, verify with speakeasy
    // For demo, we'll accept any 6-digit code
    if (!token || token.length !== 6 || !/^\d+$/.test(token)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid 2FA token'
      });
    }

    user.two_factor_enabled = true;
    await user.save();

    res.status(200).json({
      success: true,
      message: '2FA verified and enabled'
    });
  } catch (error) {
    console.error('Verify 2FA error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to verify 2FA'
    });
  }
};

// @desc    Disable 2FA
// @route   POST /api/auth/disable-2fa
// @access  Private
exports.disable2FA = async (req, res) => {
  try {
    const { password } = req.body;
    const user = await User.findById(req.user.id).select('+password');

    // Verify password
    const isPasswordValid = await user.comparePassword(password);
    if (!isPasswordValid) {
      return res.status(401).json({
        success: false,
        message: 'Password is incorrect'
      });
    }

    user.two_factor_enabled = false;
    user.two_factor_secret = undefined;
    user.two_factor_backup_codes = undefined;
    await user.save();

    res.status(200).json({
      success: true,
      message: '2FA disabled successfully'
    });
  } catch (error) {
    console.error('Disable 2FA error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to disable 2FA'
    });
  }
};

// @desc    Logout user
// @route   GET /api/auth/logout
// @access  Private
exports.logout = (req, res) => {
  res.clearCookie('token');
  res.status(200).json({
    success: true,
    message: 'Logged out successfully'
  });
};

// @desc    Get current user
// @route   GET /api/auth/me
// @access  Private
exports.getMe = async (req, res) => {
  try {
    const user = await User.findById(req.user.id)
      .select('-password -email_verification_token -phone_verification_code');

    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    res.status(200).json({
      success: true,
      data: { user }
    });
  } catch (error) {
    console.error('Get user error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to get user data'
    });
  }
};
