const mongoose = require('mongoose');
const Schema = mongoose.Schema;
const bluebird = require('bluebird');

mongoose.Promise = bluebird;
let user = null;
function userModel(connection) {
    if (user) {
        return user;
    }
    const User = new Schema({
        provider: { type: String, required: true, trim: true, default: 'local' },
        providerId: { type: String, required: false, trim: true },
        email: { type: String, required: false, trim: true },
        password: { type: String, required: false, trim: true },
        salt: { type: String, required: false, trim: true },
        role: { type: String, required: true, default: 'USER', trim: true },
        createdAt: { type: Date, required: true, default: Date.now },
        extraUserData: { type: Schema.Types.Mixed },
        userToken: { type: String, required: false, trim: true }
    });

    user = connection.model('User', User);
    return user;
}
module.exports = userModel;
