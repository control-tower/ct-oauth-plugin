const debug = require('debug')('oauth-plugin');
const Router = require('koa-router');
const ApiRouter = new Router({
    prefix: '/auth',
});
const passport = require('koa-passport');
const authServiceFunc = require('./services/auth.service');

function getUser(ctx) {
    return ctx.req.user || ctx.state.user;
}

module.exports = (plugin, connection, generalConfig) => {
    debug('Initializing services');

    const AuthService = authServiceFunc(plugin, connection);

    const API = (function api() {
        const twitter = passport.authenticate('twitter');

        const twitterCallback = passport.authenticate('twitter', {
            successRedirect: '/auth/success',
            failureRedirect: '/auth/fail',
        });

        const facebook = passport.authenticate('facebook', {
            scope: plugin.config.facebook.scope,
        });

        const facebookCallback = passport.authenticate('facebook', {
            successRedirect: '/auth/success',
            failureRedirect: '/auth/fail',
        });

        const google = passport.authenticate('google', {
            scope: plugin.config.google.scope,
        });

        const googleCallback = passport.authenticate('google', {
            successRedirect: '/auth/success',
            failureRedirect: '/auth/fail',
        });

        const localCallback = passport.authenticate('local', {
            successRedirect: '/auth/success',
            failureRedirect: '/auth/fail?error=true',
        });

        async function createToken(ctx) {
            debug('Generating token ');
            const token = await AuthService.createToken(getUser(ctx));
            return token;

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
            ctx.body = await AuthService.getUsers();
        }

        async function updateUser(ctx) {
            debug(`Update user with id ${ctx.params.id}`);
            ctx.assert(ctx.params.id, 'Id param required');

            const userUpdate = await AuthService.updateUser(ctx.params.id, ctx.request.body);
            if (!userUpdate) {
                ctx.throw(404, 'User not found');
                return;
            }
            ctx.body = userUpdate;
        }

        async function success(ctx) {
            debug('Success', ctx.session.callbackUrl);
            debug('User', getUser(ctx));
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
                } else {
                    ctx.redirect(ctx.session.callbackUrl);
                    ctx.session.callbackUrl = null;
                    ctx.session.token = null;
                }
                return;
            }
            await ctx.render('login-correct', {
                error: false,
                generalConfig,
            });
        }

        async function failAuth(ctx) {
            debug('Not authenticated');
            const thirdParty = {
                twitter: plugin.config.twitter.active,
                google: plugin.config.google.active,
                facebook: plugin.config.facebook.active,
            };
            if (ctx.query.error) {
                await ctx.render('login', {
                    error: true,
                    thirdParty,
                    generalConfig,
                });
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
            let error = null;
            if (!ctx.request.body.email || !ctx.request.body.password || !ctx.request.body.repeatPassword) {
                error = 'Email, Password and Repeat password are required';
            }
            if (ctx.request.body.password !== ctx.request.body.repeatPassword) {
                error = 'Password and Repeat password not equal';
            }
            const exist = await AuthService.existEmail(ctx.request.body.email);
            if (exist) {
                error = 'Email exist';
            }
            if (error) {
                await ctx.render('sign-up', {
                    error,
                    email: ctx.request.body.email,
                    generalConfig,
                });
                return;
            }

            try {
                await AuthService.createUser(ctx.request.body);
                await ctx.render('sign-up-correct', { generalConfig });
            } catch (err) {
                debug('Error', err);
                await ctx.render('sign-up', {
                    error: 'Error creating user.',
                    email: ctx.request.body.email,
                    generalConfig,
                });
            }
        }

        async function getSignUp(ctx) {
            await ctx.render('sign-up', { error: null, email: null, generalConfig });
        }

        async function confirmUser(ctx) {
            debug('Confirming user');
            const user = await AuthService.confirmUser(ctx.params.token);
            if (!user) {
                ctx.throw(400, 'User expired or token not found');
                return;
            }
            if (plugin.config.local.confirmUrlRedirect) {
                ctx.redirect(plugin.config.local.confirmUrlRedirect);
                return;
            }
            ctx.body = user;
        }

        async function loginView(ctx) {
            // check if the user has session
            if (getUser(ctx)) {
                debug('User has session');
                ctx.redirect('/auth/success');
                return;
            }
            const thirdParty = {
                twitter: plugin.config.twitter.active,
                google: plugin.config.google.active,
                facebook: plugin.config.facebook.active,
                basic: plugin.config.basic.active
            };
            debug(thirdParty);
            await ctx.render('login', {
                error: false,
                thirdParty,
                generalConfig,
            });
        }

        async function requestEmailResetView(ctx) {
            await ctx.render('request-mail-reset', {
                error: null,
                info: null,
                email: null,
                generalConfig,
            });
        }
        async function redirectLogin(ctx) {
            ctx.redirect('/auth/login');
        }

        async function resetPasswordView(ctx) {
            const renew = await AuthService.getRenewModel(ctx.params.token);
            let error = null;
            if (!renew) {
                error = 'Token expired';
            }
            await ctx.render('reset-password', {
                error,
                token: renew ? renew.token : null,
                generalConfig,
            });
        }

        async function sendResetMail(ctx) {
            debug('Send reset mail');
            if (!ctx.request.body.email) {
                await ctx.render('request-mail-reset', {
                    error: 'Mail required',
                    info: null,
                    email: ctx.request.body.email,
                    generalConfig,
                });
                return;
            }
            const renew = await AuthService.sendResetMail(ctx.request.body.email);
            if (!renew) {
                await ctx.render('request-mail-reset', {
                    error: 'User not found',
                    info: null,
                    email: ctx.request.body.email,
                    generalConfig,
                });
                return;
            }
            await ctx.render('request-mail-reset', {
                info: 'Email sent!!',
                error: null,
                email: ctx.request.body.email,
                generalConfig,
            });
        }

        async function resetPassword(ctx) {
            debug('Reseting password');
            let error = null;
            if (!ctx.request.body.password || !ctx.request.body.repeatPassword) {
                error = 'Password and Repeat password are required';
            }
            if (ctx.request.body.password !== ctx.request.body.repeatPassword) {
                error = 'Password and Repeat password not equal';
            }
            const exist = await AuthService.getRenewModel(ctx.params.token);
            if (!exist) {
                error = 'Token expired';
            }
            if (error) {
                await ctx.render('reset-password', {
                    error,
                    token: ctx.params.token,
                    generalConfig,
                });
                return;
            }
            const user = await AuthService.updatePassword(ctx.params.token, ctx.request.body.password);
            if (user) {
                if (plugin.config.local.confirmUrlRedirect) {
                    ctx.redirect(plugin.config.local.confirmUrlRedirect);
                    return;
                }
                ctx.body = user;
            } else {
                await ctx.render('reset-password', {
                    error: 'Error updating user',
                    token: ctx.params.token,
                    generalConfig,
                });
            }

        }

        return {
            twitter,
            twitterCallback,
            google,
            googleCallback,
            facebook,
            facebookCallback,
            localCallback,
            failAuth,
            checkLogged,
            success,
            logout,
            generateJWT,
            getUsers,
            updateUser,
            signUp,
            confirmUser,
            getSignUp,
            loginView,
            redirectLogin,
            resetPasswordView,
            requestEmailResetView,
            resetPassword,
            sendResetMail,
        };

    }());

    async function setCallbackUrl(ctx, next) {
        debug('Setting callbackUrl');
        if (ctx.query.callbackUrl) {
            ctx.session.callbackUrl = ctx.query.callbackUrl;
        }
        ctx.session.token = ctx.query.token;

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
    ApiRouter.get('/google', setCallbackUrl, API.google);
    ApiRouter.get('/google/callback', API.googleCallback);
    ApiRouter.get('/facebook', setCallbackUrl, API.facebook);
    ApiRouter.get('/facebook/callback', API.facebookCallback);
    ApiRouter.get('/basic', passport.authenticate('basic'), API.success);
    ApiRouter.get('/login', API.loginView);
    ApiRouter.post('/login', API.localCallback);
    ApiRouter.get('/fail', API.failAuth);
    ApiRouter.get('/check-logged', API.checkLogged);
    ApiRouter.get('/success', API.success);
    ApiRouter.get('/logout', setCallbackUrl, API.logout);
    ApiRouter.get('/sign-up', isLogged, isAdmin, API.getSignUp);
    ApiRouter.post('/sign-up', isLogged, isAdmin, API.signUp);
    ApiRouter.get('/confirm/:token', API.confirmUser);
    ApiRouter.get('/reset-password/:token', API.resetPasswordView);
    ApiRouter.post('/reset-password/:token', API.resetPassword);
    ApiRouter.post('/reset-password', API.sendResetMail);
    ApiRouter.get('/reset-password', API.requestEmailResetView);
    ApiRouter.get('/generate-token', isLogged, API.generateJWT);
    ApiRouter.get('/user', isLogged, isAdmin, API.getUsers);
    ApiRouter.patch('/user/:id', isLogged, isAdmin, API.updateUser);

    return ApiRouter;
};
