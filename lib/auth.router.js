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
      failureRedirect: '/auth/fail',
    });

    const facebook = passport.authenticate('facebook', {
      scope: plugin.config.facebook.scope,
    });

    const facebookCallback = passport.authenticate('facebook', {
      failureRedirect: '/auth/fail',
    });

    const google = passport.authenticate('google', {
      scope: plugin.config.google.scope,
    });

    const googleToken = passport.authenticate('google-plus-token');

    const googleCallback = passport.authenticate('google', {
      failureRedirect: '/auth/fail',
    });

    const localCallback = passport.authenticate('local', {
      successRedirect: '/auth/success',
      failureRedirect: '/auth/fail?error=true',
    });

    async function createToken(ctx, saveInUser) {
      debug('Generating token ');
      const token = await AuthService.createToken(getUser(ctx), saveInUser);
      return token;

    }

    async function generateJWT(ctx) {
      debug('Generating token');
      try {
        const token = await createToken(ctx, true);
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

    async function updateMe(ctx) {
      debug(`Update user me`);


      const userUpdate = await AuthService.updateUserMe(getUser(ctx), ctx.request.body);
      if (!userUpdate) {
        ctx.throw(404, 'User not found');
        return;
      }
      ctx.body = userUpdate;
    }

    async function createUser(ctx) {
      debug(`Create user with body ${ctx.request.body}`);
      const body = ctx.request.body;
      const user = getUser(ctx);
      if (!user) {
        ctx.throw(401, 'Not logged');
        return;
      }

      if (user.role === 'MANAGER' && body.role === 'ADMIN') {
        debug('User is manager but the new user is admin');
        ctx.throw(403, 'Forbidden');
        return;
      }

      if (!body.extraUserData || !body.extraUserData.apps)  {
        debug('Not send apps');
        ctx.throw(400, 'Apps required');
        return;
      }
      if (!user.extraUserData || !user.extraUserData.apps) {
        debug('logged user does not contain apps');
        ctx.throw(403, 'Forbidden');
        return;
      }

      const exist = await AuthService.existEmail(body.email);
      if (exist) {
        ctx.throw(400, 'Email exist');
        return;
      }

      // check Apps
      for (let i = 0, length = body.extraUserData.apps.length; i < length; i++) {
        if (user.extraUserData.apps.indexOf(body.extraUserData.apps[i]) < 0) {
          ctx.throw(403, 'Forbidden');
          return;
        }
      }

      await AuthService.createUserWithoutPassword(ctx.request.body);
      ctx.body = {};

    }

    async function success(ctx) {

      // if (ctx.session.applications) {
      //   const user = getUser(ctx);

      // }

      if (ctx.session.callbackUrl) {
        debug('Url redirect', ctx.session.callbackUrl);
        if (ctx.session.generateToken) {
          // generate token and eliminate session
          const token = await createToken(ctx, false);
          if (ctx.session.callbackUrl.indexOf('?') > -1) {
            ctx.redirect(`${ctx.session.callbackUrl}&token=${token}`);
          } else {
            ctx.redirect(`${ctx.session.callbackUrl}?token=${token}`);
          }
        } else {
          ctx.redirect(ctx.session.callbackUrl);
        }
        ctx.session.callbackUrl = null;
        ctx.session.generateToken = null;
        return;
      }
      ctx.session.callbackUrl = null;
      ctx.session.generateToken = null;
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
      ctx.redirect('/auth/login');
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
        await ctx.render('sign-up-correct', {
          generalConfig
        });
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
      await ctx.render('sign-up', {
        error: null,
        email: null,
        generalConfig
      });
    }

    async function confirmUser(ctx) {
      debug('Confirming user');
      const user = await AuthService.confirmUser(ctx.params.token);
      if (!user) {
        ctx.throw(400, 'User expired or token not found');
        return;
      }
      if (ctx.query.callbackUrl) {
        ctx.redirect(ctx.query.callbackUrl);
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

    async function updateApplications(ctx) {
      try {
        if (ctx.session && ctx.session.applications) {
          let user = getUser(ctx);
          if (user.role === 'USER') {
            user = await AuthService.updateApplicationsUser(user.id, ctx.session.applications);
          }
          delete ctx.session.applications;
          if (user) {
            ctx.login({
              id: user._id,
              provider: user.provider,
              providerId: user.providerId,
              role: user.role,
              createdAt: user.createdAt,
              extraUserData: user.extraUserData
            });
          }
        }
        ctx.redirect('/auth/success');
      } catch (err) {
        debug(err);
        ctx.redirect('/auth/fail');
      }

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
      googleToken,
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
      createUser,
      updateUser,
      updateMe,
      signUp,
      confirmUser,
      getSignUp,
      loginView,
      redirectLogin,
      resetPasswordView,
      requestEmailResetView,
      resetPassword,
      sendResetMail,
      updateApplications
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
    }
    if (!ctx.session.applications && ctx.query.applications) {
      ctx.session.applications = ctx.query.applications.split(',');
    }
    if (!ctx.session.generateToken) {
      ctx.session.generateToken = ctx.query.token === 'true';
    }

    await next();
  }

  async function setCallbackUrlOnlyWithQueryParam(ctx, next) {
    debug('Setting callbackUrl');
    if (ctx.query.callbackUrl) {
      ctx.session.callbackUrl = ctx.query.callbackUrl;
    }
    if (!ctx.session.generateToken) {
      ctx.session.generateToken = ctx.query.token === 'true';
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

  async function isAdminOrManager(ctx, next) {
    debug('Checking if user is admin or manager');
    const user = getUser(ctx);
    if (user && (user.role === 'ADMIN' || user.role === 'MANAGER')) {
      await next();
    } else {
      debug('Not admin');
      ctx.throw(401, 'Not authenticated');
    }
  }


  ApiRouter.get('/', setCallbackUrl, API.redirectLogin);
  ApiRouter.get('/twitter', setCallbackUrl, API.twitter);
  ApiRouter.get('/twitter/callback', API.twitterCallback, API.updateApplications);
  ApiRouter.get('/google', setCallbackUrl, API.google);
  ApiRouter.get('/google/callback', API.googleCallback, API.updateApplications);
  ApiRouter.get('/google/token', API.googleToken, API.generateJWT);
  ApiRouter.get('/facebook', setCallbackUrl, API.facebook);
  ApiRouter.get('/facebook/callback', API.facebookCallback, API.updateApplications);
  ApiRouter.get('/basic', passport.authenticate('basic'), API.success);
  ApiRouter.get('/login', API.loginView);
  ApiRouter.post('/login', API.localCallback);
  ApiRouter.get('/fail', API.failAuth);
  ApiRouter.get('/check-logged', API.checkLogged);
  ApiRouter.get('/success', API.success);
  ApiRouter.get('/logout', setCallbackUrlOnlyWithQueryParam, API.logout);
  ApiRouter.get('/sign-up', isLogged, isAdmin, API.getSignUp);
  ApiRouter.post('/sign-up', isLogged, isAdmin, API.signUp);
  ApiRouter.get('/confirm/:token', API.confirmUser);
  ApiRouter.get('/reset-password/:token', API.resetPasswordView);
  ApiRouter.post('/reset-password/:token', API.resetPassword);
  ApiRouter.post('/reset-password', API.sendResetMail);
  ApiRouter.get('/reset-password', API.requestEmailResetView);
  ApiRouter.get('/generate-token', isLogged, API.generateJWT);
  ApiRouter.get('/user', isLogged, isAdmin, API.getUsers);
  ApiRouter.post('/user', isLogged, isAdminOrManager, API.createUser);
  ApiRouter.patch('/user/me', isLogged, API.updateMe);
  ApiRouter.patch('/user/:id', isLogged, isAdmin, API.updateUser);

  return ApiRouter;
};
