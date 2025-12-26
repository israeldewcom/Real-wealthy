const mongoose = require('mongoose');

const depositSchema = new mongoose.Schema({
    user: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    
    amount: {
        type: Number,
        required: true,
        min: [500, 'Minimum deposit is ₦500']
    },
    
    payment_method: {
        type: String,
        enum: ['bank_transfer', 'crypto', 'paypal', 'card'],
        required: true
    },
    
    payment_proof_url: {
        type: String,
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

const Deposit = mongoose.model('Deposit', depositSchema);

module.exports = Deposit;
