const apiRouter = require('./lib/auth.router');
const passportService = require('./lib/services/passport.service');
const passport = require('koa-passport');
const debug = require('debug')('oauth-plugin');
const mongoose = require('mongoose');
const jwt = require('koa-jwt');
const views = require('koa-views');
const JWT = Promise.promisifyAll(require('jsonwebtoken'));

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
        app.use(async (ctx, next) => {
            if (ctx.headers && ctx.headers.authentication) {
                debug('Authenticated microservice with token: ', ctx.headers.authentication);
                try {
                    const service = await JWT.verify(ctx.headers.authentication, plugin.config.jwt.secret);
                    if (service) {
                        ctx.state.microservice = {
                            id: service.id,
                            name: service.name,
                            url: service.url,
                        };
                    }
                    await next();
                } catch (err) {
                    debug('Token invalid', err);
                }
            }
        });
    }
    app.use(apiRouter(plugin, connection, generalConfig).middleware());

}


module.exports = {
    middleware,
    init,
};
