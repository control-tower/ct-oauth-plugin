const mongoose = require('mongoose');
const Schema = mongoose.Schema;
const bluebird = require('bluebird');

mongoose.Promise = bluebird;

let whiteListApplication = null;

function whiteListApplicationModel(connection) {

    if (whiteListApplication) {
        return whiteListApplication;
    }

    const WhiteListApplication = new Schema({
        token: { type: String, required: true, trim: true },
        createdAt: { type: Date, required: true, default: Date.now },
    });

    whiteListApplication = connection.model('WhiteListApplication', WhiteListApplication);
    return whiteListApplication;
}

module.exports = whiteListApplicationModel;
