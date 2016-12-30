const apiRouter = require('./lib/auth.router');
const applicationRouter = require('./lib/application.router');
const passportService = require('./lib/services/passport.service');
const passport = require('koa-passport');
const debug = require('debug')('oauth-plugin');
const mongoose = require('mongoose');
const jwt = require('koa-jwt');
const views = require('koa-views');

const authServiceFunc = require('./lib/services/auth.service');
const applicationServiceFunc = require('./lib/services/application.service');
let connection = null;
let AuthService = null;
let ApplicationService = null;

function init() {

}

async function migrate() {
    debug('Executing migrate');
    const exist = await AuthService.existEmail('admin@control-tower.com');
    if (exist) {
        throw new Error('User exist');
    }
    const user = await AuthService.createUserWithoutConfirmation({
        email: 'admin@control-tower.com',
        password: 'admin'
    });
    await ApplicationService.createApplication(user._id, {
        name: 'Control Tower',
        sourceDomains: ['*']
    });
    debug('Executed migrate successfully');
}

function middleware(app, plugin, generalConfig) {
    debug('Loading oauth-plugin');
    connection = mongoose.createConnection(`${generalConfig.mongoUri}`);
    AuthService = authServiceFunc(plugin, connection);
    ApplicationService = applicationServiceFunc(plugin, connection);
    app.use(views(`${__dirname}/lib/views`, {
        map: {
            html: 'ejs',
        },
    }));
    passportService(plugin, connection);
    app.use(passport.initialize());
    app.use(passport.session());
    if (plugin.config.jwt.active) {
        debug('JWT active');
        app.use(jwt({
            secret: plugin.config.jwt.secret,
            passthrough: plugin.config.jwt.passthrough,
            isRevoked: AuthService.checkRevokedToken
        }));
    }
    app.use(apiRouter(plugin, connection, generalConfig).middleware());
    app.use(applicationRouter(plugin, connection, generalConfig).middleware());

}


module.exports = {
    middleware,
    init,
    migrate,
};
