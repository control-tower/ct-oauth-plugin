const mongoose = require('mongoose');
const Schema = mongoose.Schema;
const ObjectId = Schema.ObjectId;
const bluebird = require('bluebird');

mongoose.Promise = bluebird;
let application = null;
function applicationModel(connection) {
    if (application) {
        return application;
    }
    const Application = new Schema({
        name: { type: String, required: true, trim: true },
        slug: { type: String, required: true, trim: true, unique: true },
        allowedDomains: [{ type: String, required: false, trim: true }],
        owner: { type: ObjectId, ref: 'User', required: true },
        allowedApplications: [{ type: String, required: false, trim: true }],
        applicationToken: { type: String, required: false, trim: true }
    });

    application = connection.model('Application', Application);
    return application;
}
module.exports = applicationModel;