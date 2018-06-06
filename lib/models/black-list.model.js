const mongoose = require('mongoose');
const Schema = mongoose.Schema;
const bluebird = require('bluebird');

mongoose.Promise = bluebird;

let blackList = null;

function blackListModel(connection, plugin) {

    if (blackList) {
        return blackList;
    }

    const BlackList = new Schema({
        token: { type: String, required: true, trim: true },
        createdAt: { type: Date, required: true, default: Date.now },
    });

    BlackList.index({ token: 1 });
    blackList = connection.model('BlackList', BlackList);
    return blackList;
}

module.exports = blackListModel;
