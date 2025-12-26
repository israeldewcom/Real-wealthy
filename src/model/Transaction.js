const mongoose = require('mongoose');

const transactionSchema = new mongoose.Schema({
    user: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    
    type: {
        type: String,
        enum: ['deposit', 'withdrawal', 'investment', 'earnings', 'referral', 'bonus', 'admin_credit', 'admin_debit', 'refund', 'transfer'],
        required: true
    },
    
    amount: {
        type: Number,
        required: true
    },
    
    description: {
        type: String,
        required: true
    },
    
    reference: {
        type: String,
        required: true,
        unique: true
    },
    
    status: {
        type: String,
        enum: ['pending', 'completed', 'failed', 'cancelled'],
        default: 'pending'
    },
    
    balance_before: Number,
    balance_after: Number,
    
    metadata: {
        investment_id: mongoose.Schema.Types.ObjectId,
        deposit_id: mongoose.Schema.Types.ObjectId,
        withdrawal_id: mongoose.Schema.Types.ObjectId,
        plan_name: String,
        payment_method: String,
        admin_id: mongoose.Schema.Types.ObjectId,
        remarks: String
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
    timestamps: { createdAt: 'created_at', updatedAt: 'updated_at' }
});

const Transaction = mongoose.model('Transaction', transactionSchema);

module.exports = Transaction;
