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

        static async createApplication(ctx) {
            debug('Creating application');
            const user = getUser(ctx);
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
        return async (ctx, next) => {
            const user = getUser(ctx);
            if (!Utils.isCTRoles(user, roles)) {
                ctx.throw(401, 'Not authorized');
                return;
            }
            await next();
            return;
        };
    }

    ApiRouter.get('/', isLogged, hasRolesInCT(['MANAGER', 'ADMIN']), API.getApplications);
    ApiRouter.get('/check-token', API.checkToken);
    ApiRouter.get('/:slug', isLogged, hasRolesInCT(['MANAGER', 'ADMIN']), API.getApplicationBySlug);
    ApiRouter.post('/:slug/generate-token', isLogged, hasRolesInCT(['MANAGER', 'ADMIN']), API.generateToken);
    ApiRouter.post('/', isLogged, hasRolesInCT(['MANAGER', 'ADMIN']), API.createApplication);

    return ApiRouter;
};
