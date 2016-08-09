const mongoose = require('mongoose');
const Schema = mongoose.Schema;
const bluebird = require('bluebird');

mongoose.Promise = bluebird;

let reNew = null;

function renewModel(connection) {

    if (reNew) {
        return reNew;
    }

    const ReNew = new Schema({
        userId: { type: String, required: true, trim: true },
        token: { type: String, required: true, trim: true },
        createdAt: { type: Date, required: true, default: Date.now, expires: 60 * 60 * 24 },
    });

    reNew = connection.model('ReNew', ReNew);
    return reNew;
}

module.exports = renewModel;
