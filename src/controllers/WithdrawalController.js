const Withdrawal = require('../models/Withdrawal');
const User = require('../models/User');
const Transaction = require('../models/Transaction');
const Wallet = require('../models/Wallet');

exports.getUserWithdrawals = async (req, res) => {
    try {
        const { status, page = 1, limit = 10 } = req.query;
        const userId = req.user.id;

        // Build query
        const query = { user: userId };
        if (status) {
            query.status = status;
        }

        // Calculate skip
        const skip = (parseInt(page) - 1) * parseInt(limit);

        // Get withdrawals with pagination
        const withdrawals = await Withdrawal.find(query)
            .sort({ created_at: -1 })
            .skip(skip)
            .limit(parseInt(limit));

        // Get total count
        const total = await Withdrawal.countDocuments(query);

        res.status(200).json({
            success: true,
            data: {
                withdrawals,
                pagination: {
                    page: parseInt(page),
                    limit: parseInt(limit),
                    total,
                    pages: Math.ceil(total / parseInt(limit))
                }
            }
        });
    } catch (error) {
        console.error('Get user withdrawals error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch withdrawals'
        });
    }
};

exports.createWithdrawal = async (req, res) => {
    try {
        const { amount, payment_method } = req.body;
        const userId = req.user.id;

        // Validate amount
        if (amount < 1000) {
            return res.status(400).json({
                success: false,
                message: 'Minimum withdrawal is ₦1000'
            });
        }

        // Get user
        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        // Check if user has sufficient balance
        if (user.balance < amount) {
            return res.status(400).json({
                success: false,
                message: 'Insufficient balance'
            });
        }

        // Calculate platform fee (5%)
        const platformFee = amount * 0.05;
        const netAmount = amount - platformFee;

        // Create withdrawal
        const withdrawal = await Withdrawal.create({
            user: userId,
            amount,
            platform_fee: platformFee,
            net_amount: netAmount,
            payment_method,
            status: 'pending'
        });

        // Create transaction
        const transaction = await Transaction.create({
            user: userId,
            type: 'withdrawal',
            amount: -amount,
            description: `Withdrawal via ${payment_method}`,
            reference: `WTH-${Date.now()}-${Math.random().toString(36).substr(2, 9).toUpperCase()}`,
            status: 'pending',
            balance_before: user.balance,
            balance_after: user.balance - amount,
            metadata: {
                withdrawal_id: withdrawal._id,
                payment_method: payment_method,
                platform_fee: platformFee,
                net_amount: netAmount
            }
        });

        // Link transaction to withdrawal
        withdrawal.transaction = transaction._id;
        await withdrawal.save();

        // Deduct amount from user balance
        user.balance -= amount;
        user.total_withdrawn += amount;
        await user.save();

        // Update wallet
        await Wallet.findOneAndUpdate(
            { user: userId },
            { 
                $inc: { 
                    balance: -amount,
                    total_withdrawals: amount
                }
            }
        );

        res.status(201).json({
            success: true,
            message: 'Withdrawal request submitted successfully',
            data: { withdrawal }
        });
    } catch (error) {
        console.error('Create withdrawal error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to create withdrawal'
        });
    }
};

exports.cancelWithdrawal = async (req, res) => {
    try {
        const withdrawal = await Withdrawal.findOne({
            _id: req.params.id,
            user: req.user.id,
            status: 'pending'
        });

        if (!withdrawal) {
            return res.status(404).json({
                success: false,
                message: 'Withdrawal not found or cannot be cancelled'
            });
        }

        // Get user
        const user = await User.findById(req.user.id);

        // Refund amount to user
        user.balance += withdrawal.amount;
        user.total_withdrawn -= withdrawal.amount;
        await user.save();

        // Update wallet
        await Wallet.findOneAndUpdate(
            { user: req.user.id },
            { 
                $inc: { 
                    balance: withdrawal.amount,
                    total_withdrawals: -withdrawal.amount
                }
            }
        );

        // Update withdrawal status
        withdrawal.status = 'cancelled';
        await withdrawal.save();

        // Update transaction status
        await Transaction.findByIdAndUpdate(withdrawal.transaction, {
            status: 'cancelled'
        });

        res.status(200).json({
            success: true,
            message: 'Withdrawal cancelled successfully'
        });
    } catch (error) {
        console.error('Cancel withdrawal error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to cancel withdrawal'
        });
    }
};
