const mongoose = require('mongoose');
const Schema = mongoose.Schema;
const bluebird = require('bluebird');

mongoose.Promise = bluebird;


const User = new Schema({
    provider: { type: String, required: true, trim: true },
    providerId: { type: String, required: false, trim: true },
    email: { type: String, required: false, trim: true },
    password: { type: String, required: false, trim: true },
    salt: { type: String, required: false, trim: true },
    role: { type: String, required: true, default: 'USER', trim: true },
    createdAt: { type: Date, required: true, default: Date.now },
});

module.exports = mongoose.model('User', User);
