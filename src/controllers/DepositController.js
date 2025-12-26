const Deposit = require('../models/Deposit');
const User = require('../models/User');
const Transaction = require('../models/Transaction');
const Wallet = require('../models/Wallet');

exports.getUserDeposits = async (req, res) => {
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

        // Get deposits with pagination
        const deposits = await Deposit.find(query)
            .sort({ created_at: -1 })
            .skip(skip)
            .limit(parseInt(limit));

        // Get total count
        const total = await Deposit.countDocuments(query);

        res.status(200).json({
            success: true,
            data: {
                deposits,
                pagination: {
                    page: parseInt(page),
                    limit: parseInt(limit),
                    total,
                    pages: Math.ceil(total / parseInt(limit))
                }
            }
        });
    } catch (error) {
        console.error('Get user deposits error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch deposits'
        });
    }
};

exports.createDeposit = async (req, res) => {
    try {
        const { amount, payment_method } = req.body;
        const userId = req.user.id;

        // Validate amount
        if (amount < 500) {
            return res.status(400).json({
                success: false,
                message: 'Minimum deposit is ₦500'
            });
        }

        // Create deposit
        const deposit = await Deposit.create({
            user: userId,
            amount,
            payment_method,
            payment_proof_url: req.body.payment_proof_url,
            status: 'pending'
        });

        // Create transaction
        const transaction = await Transaction.create({
            user: userId,
            type: 'deposit',
            amount: amount,
            description: `Deposit via ${payment_method}`,
            reference: `DEP-${Date.now()}-${Math.random().toString(36).substr(2, 9).toUpperCase()}`,
            status: 'pending',
            metadata: {
                deposit_id: deposit._id,
                payment_method: payment_method
            }
        });

        // Link transaction to deposit
        deposit.transaction = transaction._id;
        await deposit.save();

        res.status(201).json({
            success: true,
            message: 'Deposit request submitted successfully',
            data: { deposit }
        });
    } catch (error) {
        console.error('Create deposit error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to create deposit'
        });
    }
};

exports.cancelDeposit = async (req, res) => {
    try {
        const deposit = await Deposit.findOne({
            _id: req.params.id,
            user: req.user.id,
            status: 'pending'
        });

        if (!deposit) {
            return res.status(404).json({
                success: false,
                message: 'Deposit not found or cannot be cancelled'
            });
        }

        // Update deposit status
        deposit.status = 'cancelled';
        await deposit.save();

        // Update transaction status
        await Transaction.findByIdAndUpdate(deposit.transaction, {
            status: 'cancelled'
        });

        res.status(200).json({
            success: true,
            message: 'Deposit cancelled successfully'
        });
    } catch (error) {
        console.error('Cancel deposit error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to cancel deposit'
        });
    }
};
