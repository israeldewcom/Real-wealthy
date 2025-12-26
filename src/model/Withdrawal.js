const mongoose = require('mongoose');

const withdrawalSchema = new mongoose.Schema({
    user: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    
    amount: {
        type: Number,
        required: true,
        min: [1000, 'Minimum withdrawal is ₦1000']
    },
    
    platform_fee: {
        type: Number,
        default: 0
    },
    
    net_amount: {
        type: Number,
        required: true
    },
    
    payment_method: {
        type: String,
        enum: ['bank_transfer', 'crypto', 'paypal'],
        required: true
    },
    
    status: {
        type: String,
        enum: ['pending', 'completed', 'rejected', 'cancelled'],
        default: 'pending'
    },
    
    transaction: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Transaction'
    },
    
    transaction_id: String,
    
    processed_by: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User'
    },
    
    processed_at: Date,
    
    remarks: String,
    
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

const Withdrawal = mongoose.model('Withdrawal', withdrawalSchema);

module.exports = Withdrawal;
