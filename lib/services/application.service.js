const debug = require('debug')('oauth-plugin');
const slug = require('slug');
const Utils = require('../utils');
const Promise = require('bluebird');
const JWT = Promise.promisifyAll(require('jsonwebtoken'));

const userModelFunc = require('../models/user.model');
const whiteListApplicationModelFunc = require('../models/white-list-application.model');
const applicationModelFunc = require('../models/application.model');
const ApplicationDuplicated = require('../errors/applicationDuplicated.error');
const UserNotAuthorized = require('../errors/userNotAuthorized.error');
const ApplicationNotFound = require('../errors/applicationNotFound.error');
const UserNotFound = require('../errors/userNotFound.error');

slug.defaults.modes.pretty = {
  replacement: '-',
  symbols: false,
  remove: /[.]/g,
  lower: true,
  charmap: slug.charmap,
  multicharmap: slug.multicharmap
};

function applicationService(plugin, connection) {

  const UserModel = userModelFunc(connection);
  const ApplicationModel = applicationModelFunc(connection);
  const WhiteListApplicationModel = whiteListApplicationModelFunc(connection);

  class ApplicationService {

    static async getApplicationBrandBySlug(slug) {
      return await ApplicationModel.findOne({ slug }).select('color image customCSS name');
    }

    static async getApplications(user) {
      if (Utils.isCTAdmin(user)) {
        return await ApplicationModel.find().select('-__v').populate('owner', 'email _id');
      }
      debug('User', JSON.stringify(user));
      const userDB = await UserModel.findById(user.id).populate('roles.application', '-owner -__v');
      return userDB.roles.map((role) => Object.assign({}, role.application._doc, {
        role: role.role
      }));
    }

    static async getApplicationBySlug(user, appSlug) {
      if (Utils.isCTAdmin(user)) {
        return await ApplicationModel.findOne({
          slug: appSlug
        }).select('-__v').populate('owner', 'email _id');
      }

      const userDB = await UserModel.findById(user.id).populate('roles.application');

      const app = userDB.roles.filter((role) => role.application.slug === appSlug).map((role) => Object.assign({}, role.application._doc, {
        role: role.role
      }));
      if (app && app.length > 0) {
        return app[0];
      }
      return {};
    }

    static async getUsersOfApplication(appSlug) {

      const application = await ApplicationModel.findOne({
        slug: appSlug
      });
      if (!application) {
        throw new ApplicationNotFound(`Application ${appSlug} not found`);
      }
      return UserModel.find({
        'roles.application': application._id
      }).select('-__v -password -salt -userToken').populate('roles.application', 'slug -_id');
    }

    static async createApplication(userId, content) {
      debug('Checking if application exist with the same name', content.name);
      const slugName = slug(content.name);
      let application = await ApplicationModel.findOne({
        slug: slugName
      });
      if (application) {
        throw new ApplicationDuplicated('Already exist application with name ', content.name);
      }
      content.owner = userId;
      content.slug = slugName;
      if (!content.allowedDomains || content.allowedDomains.length === 0) {
        content.allowedDomains = ['*'];
      }

      if (!content.allowedApplications || content.allowedApplications.length === 0) {
        content.allowedApplications = [];
      }

      application = await new ApplicationModel(content).save();

      debug('Setting application role in user');
      const user = await UserModel.findOne({
        _id: userId
      });
      if (!user) {
        throw new Error('User not found');
      }
      if (!user.roles) {
        user.roles = [];
      }
      user.roles.push({
        application: application._id, // eslint-disable-line no-underscore-dangle
        role: 'ADMIN'
      });
      await user.save();
      return await ApplicationModel.findById(application._id).select('-__v').populate('owner', 'email _id');
    }


    static async generateToken(user, applicationSlug) {
      debug('Checking if user has permissions');
      if (!Utils.isCTAdmin(user) && !Utils.isAdminInApplication(user, applicationSlug)) {
        throw new UserNotAuthorized('User doesn\'t have permissions');
      }
      const application = await ApplicationModel.findOne({
        slug: applicationSlug
      }).populate('owner', 'email _id');

      const token = await JWT.sign({
        name: application.name,
        slug: application.slug,
        owner: application.owner,
        allowedApplications: application.allowedApplications,
        allowedDomains: application.allowedDomains
      }, plugin.config.application.secret, {});

      debug('Deleting old application token of white-list');
      await WhiteListApplicationModel.remove({
        token: application.applicationToken
      });
      debug('Saving new token');
      await new WhiteListApplicationModel({
        token
      }).save();
      await WhiteListApplicationModel.findOneAndUpdate({
        slug: applicationSlug
      }, {
        $set: {
          applicationToken: token
        }
      });

      return {
        token
      };
    }

    static async checkTokenApplication(token) {
      debug('Checking if token is revoked');
      const exist = await WhiteListApplicationModel.findOne({
        token
      });
      if (!exist) {
        return null;
      }
      try {
        return JWT.verify(token, plugin.config.application.secret);
      } catch (e) {
        debug('Invalid token');
        return null;
      }
    }

    static async associateApplication(app, email, role) {
      debug('Associating application to user');
      const application = await ApplicationModel.findOne({
        slug: app
      });
      if (!application) {
        throw new ApplicationNotFound(`Application ${app} not found`);
      }
      const user = await UserModel.findOne({
        email
      }).populate('roles.application');

      if (!user) {
        throw new UserNotFound(`User with id ${email} not found`);
      }

      // check if the role exists
      let found = false;
      if (user.roles) {
        for (let i = 0, length = user.roles.length; i < length; i++) {
          if (user.roles[i].application.slug === app) {
            found = true;
            break;
          }
        }
      }
      if (found) {
        debug('Application already associated');
        return {};
      }

      user.roles.push({
        application,
        role
      });
      await user.save();
      return {};

    }

  }

  return ApplicationService;

}
module.exports = applicationService;
