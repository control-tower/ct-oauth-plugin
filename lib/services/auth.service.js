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
                        createdAt: Date.now()
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
            }).exec();
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

        static async confirmUser(confirmationToken) {
            const exist = await UserTempModel.findOne({ confirmationToken });
            if (!exist) {
                return null;
            }
            const user = await new UserModel({
                email: exist.email,
                password: exist.password,
                salt: exist.salt,
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
            const user = await WhiteListModel.findOne({ token });

            if (!user) {
                debug('Token revoked!!!!');
                throw new Error('Revoked token');
            }
            return true;
        }

    }

    return AuthService;

}
module.exports = authService;
