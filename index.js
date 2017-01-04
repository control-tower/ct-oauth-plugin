const apiRouter = require('./lib/auth.router');
const passportService = require('./lib/services/passport.service');
const passport = require('koa-passport');
const debug = require('debug')('oauth-plugin');
const mongoose = require('mongoose');
const jwt = require('koa-jwt');
const views = require('koa-views');

// const authServiceFunc = require('./lib/services/auth.service');

function init() {

}

function middleware(app, plugin, generalConfig) {
    debug('Loading oauth-plugin');
    const connection = mongoose.createConnection(`${generalConfig.mongoUri}`);
    // const AuthService = authServiceFunc(plugin, connection);
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
            // isRevoked: AuthService.checkRevokedToken
        }));
    }
    app.use(apiRouter(plugin, connection, generalConfig).middleware());

}


module.exports = {
    middleware,
    init,
};
