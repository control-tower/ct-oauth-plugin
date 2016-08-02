const apiRouter = require('./lib/auth.router');
const authService = require('./lib/auth.service');
const passport = require('koa-passport');
const debug = require('debug')('oauth-plugin');
const mongoose = require('mongoose');
const jwt = require('koa-jwt');
const views = require('koa-views');

function init() {

}

function middleware(app, plugin, generalConfig) {
    mongoose.createConnection(`${generalConfig.mongoUri}/users`);
    debug('Loading oauth-plugin');

    app.use(views(`${__dirname}/lib/views`, {
        map: {
            html: 'ejs',
        },
    }));
    authService(plugin);
    app.use(passport.initialize());
    app.use(passport.session());
    if (plugin.config.jwt.active) {
        app.use(jwt({
            secret: plugin.config.jwt.secret,
            passthrough: plugin.config.jwt.passthrough,
        }));
    }
    app.use(apiRouter(plugin).middleware());

}


module.exports = {
    middleware,
    init,
};
