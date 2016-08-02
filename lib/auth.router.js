const debug = require('debug')('oauth-plugin');
const Router = require('koa-router');
const bcrypt = require('bcrypt');
const ApiRouter = new Router({
    prefix: '/auth',
});
const passport = require('koa-passport');
const Promise = require('bluebird');
const JWT = Promise.promisifyAll(require('jsonwebtoken'));
const UserModel = require('./user.model');

function getUser(ctx) {
    return ctx.req.user || ctx.state.user;
}

module.exports = (plugin) => {

    const API = (function api() {
        const twitter = passport.authenticate('twitter');

        const twitterCallback = passport.authenticate('twitter', {
            successRedirect: '/auth/success',
            failureRedirect: '/auth/fail',
        });

        const localCallback = passport.authenticate('local', {
            successRedirect: '/auth/success',
            failureRedirect: '/auth/fail?error=true',
        });

        async function createToken(ctx) {
            debug('Generating token ');
            try {
                const options = {};
                if (plugin.config.jwt.expiresInMinutes && plugin.config.jwt.expiresInMinutes > 0) {
                    options.expiresInMinutes = 60 * 5;
                }
                const token = await JWT.sign(getUser(ctx), plugin.config.jwt.secret, options);
                return token;
            } catch (e) {
                debug('Error to generate token', e);
                return null;
            }
        }

        async function generateJWT(ctx) {
            debug('Generating token');
            try {
                const token = await createToken(ctx);
                debug(token);
                ctx.body = {
                    token,
                };
            } catch (e) {
                debug(e);
            }
        }

        async function checkLogged(ctx) {
            if (getUser(ctx)) {
                ctx.body = getUser(ctx);
            } else {
                ctx.res.statusCode = 401;
                ctx.throw(401, 'Not authenticated');
            }
        }

        async function getUsers(ctx) {
            debug('Get Users');
            ctx.body = await UserModel.find({}, {
                __v: 0,
            }).exec();
        }

        async function updateUser(ctx) {
            debug(`Update user with id ${ctx.params.id}`);
            ctx.assert(ctx.params.id, 'Id param required');
            const user = await UserModel.findById(ctx.params.id).exec();
            if (!user) {
                ctx.throw(404, 'User not found');
                return;
            }
            if (ctx.request.body.role) {
                user.role = ctx.request.body.role;
            }
            const userUpdate = await user.save();

            ctx.body = userUpdate;
        }

        async function success(ctx) {
            debug('Success', ctx.session.callbackUrl);

            if (ctx.session.callbackUrl) {
                debug('Url redirect', ctx.session.callbackUrl);
                if (ctx.session.token) {
                    // generate token and eliminate session
                    const token = await createToken(ctx);
                    if (ctx.session.callbackUrl.indexOf('?') > -1) {
                        ctx.redirect(`${ctx.session.callbackUrl}&token=${token}`);
                    } else {
                        ctx.redirect(`${ctx.session.callbackUrl}?token=${token}`);
                    }
                    ctx.session = null;
                } else {
                    ctx.redirect(ctx.session.callbackUrl);
                    ctx.session.callbackUrl = null;
                    ctx.session.token = null;
                }
                return;
            }
            ctx.body = getUser(ctx);
        }

        async function failAuth(ctx) {
            debug('Not authenticated');
            if (ctx.query.error) {
                await ctx.render('login', { error: true });
            } else {
                ctx.throw(401, 'Not authenticated');
            }
        }

        async function logout(ctx) {
            ctx.logout();
            ctx.body = '';
        }

        async function signUp(ctx) {
            debug('Creating user');
            ctx.assert(ctx.request.body.email, 400, 'Email required');
            ctx.assert(ctx.request.body.password, 400, 'Password required');
            const exist = await UserModel.findOne({
                email: ctx.request.body.email,
            });
            if (exist) {
                ctx.throw(400, 'Email duplicated');
                return;
            }
            const salt = bcrypt.genSaltSync();
            const user = await new UserModel({
                provider: 'local',
                email: ctx.request.body.email,
                password: bcrypt.hashSync(ctx.request.body.password, salt),
                salt,
            }).save();
            // delete user.password;
            ctx.body = user;
        }

        async function loginView(ctx) {
            await ctx.render('login', {
                error: false,
            });
        }
        async function redirectLogin(ctx) {
            ctx.redirect('/auth/login');
        }

        return {
            twitter,
            twitterCallback,
            localCallback,
            failAuth,
            checkLogged,
            success,
            logout,
            generateJWT,
            getUsers,
            updateUser,
            signUp,
            loginView,
            redirectLogin,
        };

    }());

    async function setCallbackUrl(ctx, next) {
        debug('Setting callbackUrl');
        if (!ctx.session.callbackUrl) {
            if (ctx.query.callbackUrl) {
                ctx.session.callbackUrl = ctx.query.callbackUrl;
            } else {
                ctx.session.callbackUrl = ctx.headers.referer;
            }
            ctx.session.token = ctx.query.token;
        }
        await next();
    }

    async function isLogged(ctx, next) {
        debug('Checking if user is logged');
        if (getUser(ctx)) {
            await next();
        } else {
            debug('Not logged');
            ctx.throw(401, 'Not authenticated');
        }
    }

    async function isAdmin(ctx, next) {
        debug('Checking if user is admin');
        const user = getUser(ctx);
        if (user && user.role === 'ADMIN') {
            await next();
        } else {
            debug('Not admin');
            ctx.throw(401, 'Not authenticated');
        }
    }

    ApiRouter.get('/', setCallbackUrl, API.redirectLogin);
    ApiRouter.get('/twitter', setCallbackUrl, API.twitter);
    ApiRouter.get('/twitter/callback', API.twitterCallback);
    ApiRouter.get('/login', API.loginView);
    ApiRouter.post('/login', API.localCallback);
    ApiRouter.get('/fail', API.failAuth);
    ApiRouter.get('/checkLogged', API.checkLogged);
    ApiRouter.get('/success', API.success);
    ApiRouter.get('/logout', API.logout);
    ApiRouter.post('/signUp', API.signUp);
    ApiRouter.get('/generate-token', isLogged, API.generateJWT);
    ApiRouter.get('/user', isLogged, isAdmin, API.getUsers);
    ApiRouter.patch('/user/:id', isLogged, isAdmin, API.updateUser);

    return ApiRouter;
};
