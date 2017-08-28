const debug = require('debug')('oauth-plugin');
const Router = require('koa-router');
const ApiRouter = new Router({
  prefix: '/auth/application',
});
const authServiceFunc = require('./services/auth.service');
const applicationServiceFunc = require('./services/application.service');
const Utils = require('./utils');

function getUser(ctx) {
  if (ctx.state) {
    if (ctx.state.user) {
      return ctx.state.user;
    } else if (ctx.state.microservice) {
      return ctx.state.microservice;
    }
  }
  if (ctx.req && ctx.req.user) {
    return ctx.req.user;
  }
  return null;
}

module.exports = (plugin, connection, generalConfig) => {
  debug('Initializing services');

  const AuthService = authServiceFunc(plugin, connection);
  const ApplicationService = applicationServiceFunc(plugin, connection);

  class API {

    static async getApplications(ctx) {
      debug('Get applications');
      const user = getUser(ctx);
      const apps = await ApplicationService.getApplications(user);
      ctx.body = apps;
    }

    static async getApplicationBySlug(ctx) {
      debug('Get application by slug', ctx.params.slug);
      const user = getUser(ctx);
      const apps = await ApplicationService.getApplicationBySlug(user, ctx.params.slug);
      ctx.body = apps;
    }

    static async getUserOfApplication(ctx) {
      debug('Get users of application with slug', ctx.params.slug);
      const users = await ApplicationService.getUsersOfApplication(ctx.params.slug);
      ctx.body = users;
    }

    static async createApplication(ctx) {
      debug('Creating application');
      const user = getUser(ctx);
      ctx.assert(ctx.request.body.name, 400, 'Name is required');
      ctx.body = await ApplicationService.createApplication(user.id, ctx.request.body);
    }

    static async generateToken(ctx) {
      debug('Generating token');
      const user = getUser(ctx);
      ctx.body = await ApplicationService.generateToken(user, ctx.params.slug);
    }

    static async checkToken(ctx) {
      debug('Checking token');
      ctx.body = await ApplicationService.checkTokenApplication(ctx.headers.application);
    }

    static async associateApplication(ctx) {
      debug(`Associating app ${ctx.params.slug} to user`);
      ctx.assert(ctx.request.body.role, 400, 'Role is required');
      ctx.assert(['ADMIN', 'MANAGER', 'USER'].indexOf(ctx.request.body.role) >= 0, 400, 'Role not allowed');
      ctx.assert(ctx.request.body.email, 400, 'Email is required');
      const user = getUser(ctx);
      for (let i = 0, length = user.roles.length; i < length; i++) {
        if (user.roles[i].name === ctx.params.slug) {
          if (user.roles[i].role === 'MANAGER' && ctx.request.body.role === 'ADMIN') {
            ctx.throw(401, 'Not authorized');
            return;
          }
        }
      }

      ctx.body = await ApplicationService.associateApplication(ctx.params.slug, ctx.request.body.email, ctx.request.body.role);
    }

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

  function hasRolesInCT(roles) {
    return async(ctx, next) => {
      const user = getUser(ctx);
      if (!Utils.isCTRoles(user, roles)) {
        ctx.throw(401, 'Not authorized');
        return;
      }
      await next();
      return;
    };
  }

  async function isAdminInApp(ctx, next) {
    const user = getUser(ctx);
    if (!Utils.isAdminInApp(user, ctx.params.slug)) {
      ctx.throw(401, 'Not authorized');
      return;
    }
    await next();
    return;
  }

  function hasRolesInApp(roles) {
    return async(ctx, next) => {
      const user = getUser(ctx);
      if (!Utils.hasRolesInApp(user, ctx.params.slug, roles)) {
        ctx.throw(401, 'Not authorized');
        return;
      }
      await next();
      return;
    };
  }

  ApiRouter.get('/', isLogged, hasRolesInCT(['MANAGER', 'ADMIN', 'USER']), API.getApplications);
  ApiRouter.get('/check-token', API.checkToken);
  ApiRouter.get('/:slug', isLogged, hasRolesInCT(['MANAGER', 'ADMIN', 'USER']), API.getApplicationBySlug);
  ApiRouter.get('/:slug/user', isLogged, isAdminInApp, API.getUserOfApplication);
  ApiRouter.post('/:slug/generate-token', isLogged, hasRolesInCT(['ADMIN']), API.generateToken);
  ApiRouter.post('/', isLogged, hasRolesInCT(['MANAGER', 'ADMIN']), API.createApplication);
  ApiRouter.post('/:slug/associate', isLogged, hasRolesInApp(['MANAGER', 'ADMIN']), API.associateApplication);
  // ApiRouter.delete('/:slug/:userId', isLogged, hasRolesInApp(['MANAGER', 'ADMIN']), API.desassociateApplication);

  return ApiRouter;
};
