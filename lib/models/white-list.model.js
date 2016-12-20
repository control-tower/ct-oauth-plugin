const mongoose = require('mongoose');
const Schema = mongoose.Schema;
const bluebird = require('bluebird');

mongoose.Promise = bluebird;

let whiteList = null;

function whiteListModel(connection, plugin) {

    if (whiteList) {
        return whiteList;
    }
    let expires = 24 * 60 * 60;
    if (plugin.config.jwt.expiresInMinutes && plugin.config.jwt.expiresInMinutes > 0) {
        expires = plugin.config.jwt.expiresInMinutes * 60;
    }

    const WhiteList = new Schema({
        token: { type: String, required: true, trim: true },
        createdAt: { type: Date, required: true, default: Date.now, expires },
    });

    whiteList = connection.model('WhiteList', WhiteList);
    return whiteList;
}

module.exports = whiteListModel;
