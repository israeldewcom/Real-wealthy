const User = require('../models/User');
const Investment = require('../models/Investment');
const Transaction = require('../models/Transaction');

exports.getProfile = async (req, res) => {
    try {
        const user = await User.findById(req.user.id)
            .select('-password -password_reset_token -email_verification_token');

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
        console.error('Get profile error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to get profile'
        });
    }
};

exports.updateProfile = async (req, res) => {
    try {
        const { full_name, phone, country } = req.body;

        const user = await User.findByIdAndUpdate(
            req.user.id,
            { full_name, phone, country },
            { new: true, runValidators: true }
        ).select('-password');

        res.status(200).json({
            success: true,
            message: 'Profile updated successfully',
            data: { user }
        });
    } catch (error) {
        console.error('Update profile error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to update profile'
        });
    }
};

exports.updateBankDetails = async (req, res) => {
    try {
        const { bank_name, account_name, account_number } = req.body;

        const user = await User.findByIdAndUpdate(
            req.user.id,
            {
                bank_details: {
                    bank_name,
                    account_name,
                    account_number,
                    verified: false
                }
            },
            { new: true }
        ).select('-password');

        res.status(200).json({
            success: true,
            message: 'Bank details updated successfully',
            data: { user }
        });
    } catch (error) {
        console.error('Update bank details error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to update bank details'
        });
    }
};

exports.getDashboardStats = async (req, res) => {
    try {
        const userId = req.user.id;

        // Get user
        const user = await User.findById(userId);

        // Get investment stats
        const investmentStats = await Investment.aggregate([
            { $match: { user: user._id } },
            {
                $group: {
                    _id: null,
                    total_invested: { $sum: '$amount' },
                    total_earned: { $sum: '$total_earned' },
                    active_investments: { 
                        $sum: { $cond: [{ $eq: ['$status', 'active'] }, 1, 0] }
                    },
                    active_investment_value: {
                        $sum: { $cond: [{ $eq: ['$status', 'active'] }, '$amount', 0] }
                    }
                }
            }
        ]);

        // Get recent transactions
        const transactions = await Transaction.find({ user: userId })
            .sort({ created_at: -1 })
            .limit(5);

        // Get active investments
        const activeInvestments = await Investment.find({ 
            user: userId, 
            status: 'active' 
        })
        .populate('plan', 'name daily_interest total_interest duration')
        .limit(5);

        const stats = investmentStats[0] || {
            total_invested: 0,
            total_earned: 0,
            active_investments: 0,
            active_investment_value: 0
        };

        // Calculate daily earnings from active investments
        let dailyEarnings = 0;
        activeInvestments.forEach(inv => {
            dailyEarnings += (inv.amount * inv.daily_interest) / 100;
        });

        // Generate sample earnings data for chart
        const earningsData = [];
        for (let i = 6; i >= 0; i--) {
            const date = new Date();
            date.setDate(date.getDate() - i);
            earningsData.push({
                date: date.toISOString().split('T')[0],
                earnings: Math.floor(dailyEarnings * (0.8 + Math.random() * 0.4))
            });
        }

        res.status(200).json({
            success: true,
            data: {
                user: {
                    balance: user.balance,
                    total_earnings: user.total_earnings,
                    referral_earnings: user.referral_earnings
                },
                dashboard_stats: {
                    ...stats,
                    daily_earnings: dailyEarnings
                },
                daily_earnings: earningsData,
                active_investments,
                recent_transactions: transactions
            }
        });
    } catch (error) {
        console.error('Get dashboard stats error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to get dashboard stats'
        });
    }
};
