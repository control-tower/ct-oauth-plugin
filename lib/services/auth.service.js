const debug = require('debug')('oauth-plugin');
const Promise = require('bluebird');
const JWT = Promise.promisifyAll(require('jsonwebtoken'));
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const userModelFunc = require('../models/user.model');
const renewModelFunc = require('../models/renew.model');
const userTempModelFunc = require('../models/user-temp.model');
const whiteListModelFunc = require('../models/white-list.model');
const mailServiceFunc = require('./mail.service');

function authService(plugin, connection) {

    const MailService = mailServiceFunc(plugin);
    const UserModel = userModelFunc(connection);
    const UserTempModel = userTempModelFunc(connection);
    const WhiteListModel = whiteListModelFunc(connection, plugin);
    const RenewModel = renewModelFunc(connection);

    class AuthService {

        static async createToken(user, saveInUser) {
            try {
                const options = {};
                if (plugin.config.jwt.expiresInMinutes && plugin.config.jwt.expiresInMinutes > 0) {
                    options.expiresIn = plugin.config.jwt.expiresInMinutes * 60;
                }

                const userData = await UserModel.findById(user.id);
                let token = null;

                if (userData) {
                    const dataToken = {
                        id: userData._id, // eslint-disable-line no-underscore-dangle
                        role: userData.role,
                        provider: userData.provider,
                        email: userData.email,
                        extraUserData: userData.extraUserData,
                        createdAt: Date.now(),
                        photo: userData.photo,
                        name: userData.name
                    };
                    token = await JWT.sign(dataToken, plugin.config.jwt.secret, options);
                    if (saveInUser) {
                        await WhiteListModel.remove({ token: userData.userToken });
                        userData.userToken = token;
                        await userData.save();
                    }
                } else {
                    const dataToken = Object.assign({}, user);
                    delete dataToken.exp;
                    dataToken.createdAt = Date.now();
                    token = await JWT.sign(dataToken, plugin.config.jwt.secret, options);
                }
                await new WhiteListModel({ token }).save();

                return token;
            } catch (e) {
                debug('Error to generate token', e);
                return null;
            }
        }

        static async getUsers() {
            return await UserModel.find({}, {
                __v: 0,
            }).select('-password -salt -userToken').exec();
        }

        static async updateUser(id, data) {
            const user = await UserModel.findById(id).exec();
            if (!user) {
                return null;
            }
            if (data.role) {
                user.role = data.role;
            }
            if (data.extraUserData) {
                user.extraUserData = data.extraUserData;
            }
            const userUpdate = await user.save();
            return userUpdate;
        }


        static async updateUserMe(me, data) {
            const user = await UserModel.findById(me.id).exec();
            if (!user) {
                return null;
            }
            if (data.name) {
                user.name = data.name;
            }
            if (data.photo) {
                user.photo = data.photo;
            }
            if (data.email && user.provider !== 'local') {
                user.email = data.email;
            }
            const userUpdate = await user.save();
            return userUpdate;
        }

        static async existEmail(email) {
            const exist = await UserModel.findOne({
                email,
            });

            const existTemp = await UserTempModel.findOne({
                email,
            });

            return exist || existTemp;
        }

        static async createUser(data) {
            const salt = bcrypt.genSaltSync();

            const user = await new UserTempModel({
                provider: 'local',
                email: data.email,
                role: data.role || 'USER',
                password: bcrypt.hashSync(data.password, salt),
                confirmationToken: crypto.randomBytes(20).toString('hex'),
                salt,
            }).save();

            debug('Sending mail');
            try {
                await MailService.sendConfirmationMail({
                    email: user.email,
                    confirmationToken: user.confirmationToken,
                }, [{ address: user.email }]);
            } catch (err) {
                debug('Error', err);
                throw err;
            }

        }

        static async createUserWithoutPassword(data) {
            const salt = bcrypt.genSaltSync();
            const pass = crypto.randomBytes(8).toString('hex');
            const user = await new UserTempModel({
                provider: 'local',
                email: data.email,
                role: data.role,
                password: bcrypt.hashSync(pass, salt),
                confirmationToken: crypto.randomBytes(20).toString('hex'),
                salt,
                extraUserData: data.extraUserData,
            }).save();

            debug('Sending mail');
            try {
                await MailService.sendConfirmationMailWithPassword({
                    email: user.email,
                    confirmationToken: user.confirmationToken,
                    password: pass,
                    callbackUrl: data.callbackUrl || ''
                }, [{ address: user.email }]);
            } catch (err) {
                debug('Error', err);
                throw err;
            }

        }

        static async confirmUser(confirmationToken) {
            const exist = await UserTempModel.findOne({ confirmationToken });
            if (!exist) {
                return null;
            }
            const user = await new UserModel({
                email: exist.email,
                password: exist.password,
                salt: exist.salt,
                role: exist.role,
                extraUserData: exist.extraUserData,
                provider: 'local',
            }).save();
            await exist.remove();
            delete user.password;
            delete user.salt;

            return user;
        }

        static async getRenewModel(token) {
            debug('obtaining renew model of token', token);
            const renew = await RenewModel.findOne({ token });
            return renew;
        }

        static async sendResetMail(email) {
            debug('Generating token to email', email);

            const user = await UserModel.findOne({ email });
            if (!user) {
                debug('User not found');
                return null;
            }

            const renew = await new RenewModel({
                userId: user._id,
                token: crypto.randomBytes(20).toString('hex'),
            }).save();

            await MailService.sendRecoverPasswordMail({
                token: renew.token,
            }, [{ address: user.email }]);

            return renew;
        }

        static async updatePassword(token, newPassword) {
            debug('Updating password');
            const renew = await RenewModel.findOne({ token });
            if (!renew) {
                debug('Token not found');
                return null;
            }
            const user = await UserModel.findById(renew.userId);
            if (!user) {
                debug('User not found');
                return null;
            }
            const salt = bcrypt.genSaltSync();
            user.password = bcrypt.hashSync(newPassword, salt);
            user.salt = salt;
            await user.save();
            return user;
        }

        static async checkRevokedToken(ctx, token) {
            debug('Checking if token is revoked');
            try {
                debug('token', token);
                const user = await WhiteListModel.findOne({ token });

                if (!user) {
                    debug('Token revoked!!!!');
                    return true;
                }
                return false;
            } catch(e) {
                debug(e);
                return true;
            }
        }

        static async updateApplicationsUser(id, applications) {
          debug('Searching user with id ', id, applications);
          const user = await UserModel.findById(id);
          if (!user) {
              debug('User not found');
              return null;
          }
          if (!user.extraUserData) {
            user.extraUserData = {
              apps: []
            };
          } else {
            user.extraUserData = Object.assign({}, user.extraUserData);
          }
          for (let i = 0, length = applications.length; i < length; i++) {
            if (user.extraUserData.apps.indexOf(applications[i]) === -1) {
              user.extraUserData.apps.push(applications[i].toLowerCase());
            }
          }
          user.markModified('extraUserData');
          await user.save();
          return user;
        }

    }

    return AuthService;

}
module.exports = authService;
