const mongoose = require('mongoose');
const Schema = mongoose.Schema;
const bluebird = require('bluebird');

mongoose.Promise = bluebird;
let userTemp = null;

function userTempModel(connection) {
    if (userTemp) {
        return userTemp;
    }
    const UserTemp = new Schema({
        email: { type: String, required: false, trim: true },
        password: { type: String, required: false, trim: true },
        salt: { type: String, required: false, trim: true },
        role: { type: String, required: true, default: 'USER', trim: true },
        createdAt: { type: Date, required: true, default: Date.now, expires: 60 * 60 * 24 * 7 },
        confirmationToken: { type: String, required: true, trim: true },
    });

    userTemp = connection.model('UserTemp', UserTemp);
    return userTemp;
}

module.exports = userTempModel;
