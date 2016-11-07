const passport = require('koa-passport');
const debug = require('debug')('oauth-plugin');
const BasicStrategy = require('passport-http').BasicStrategy;
const TwitterStrategy = require('passport-twitter').Strategy;
const FacebookStrategy = require('passport-facebook').Strategy;
const GoogleStrategy = require('passport-google-oauth').OAuth2Strategy;
const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcrypt');
const userModelFunc = require('../models/user.model');


function passportService(plugin, connection) {
    const UserModel = userModelFunc(connection);
    async function registerUser(accessToken, refreshToken, profile, done) {
        debug('Registering user');
        let user = await UserModel.findOne({
            provider: profile.provider,
            providerId: profile.id,
        }).exec();
        debug(user);
        if (!user) {
            debug('Not exist user');
            user = await new UserModel({
                provider: profile.provider,
                providerId: profile.id,
            }).save();
        }
        debug('Returning user', user);
        done(null, {
            id: user._id,
            provider: user.provider,
            providerId: user.providerId,
            role: user.role,
            createdAt: user.createdAt,
            extraUserData: user.extraUserData
        });
    }

    async function registerUserBasic(userId, password, done) {
        try {
            debug('Verifing basic auth');
            if (userId === plugin.config.basic.userId && password === plugin.config.basic.password) {
                done(null, {
                    provider: 'basic',
                    role: plugin.config.basic.role,
                });
            } else {
                done(null, false);
            }
        } catch(e) {
            debug(e);
        }
    }

    passport.serializeUser((user, done) => {
        done(null, user);
    });

    passport.deserializeUser((user, done) => {
        done(null, user);
    });

    if (plugin.config.local && plugin.config.local.active) {
        debug('Loading local strategy');
        const login = async function(username, password, done) {
            const user = await UserModel.findOne({
                email: username,
            }).exec();
            if (user && user.salt && user.password === bcrypt.hashSync(password, user.salt)) {
                done(null, {
                    id: user._id,
                    provider: user.provider,
                    providerId: user.providerId,
                    email: user.email,
                    role: user.role,
                    createdAt: user.createdAt,
                    extraUserData: user.extraUserData
                });
            } else {
                done(null, false);
            }
        };
        const localStrategy = new LocalStrategy({
            usernameField: 'email',
            passwordField: 'password',
        }, login);
        passport.use(localStrategy);
    }

    if (plugin.config.basic && plugin.config.basic.active) {
        debug('Loading basic strategy');
        const basicStrategy = new BasicStrategy(registerUserBasic);
        passport.use(basicStrategy);
    }

    if (plugin.config.twitter && plugin.config.twitter.active) {
        debug('Loading twitter strategy');
        const configTwitter = {
            consumerKey: plugin.config.twitter.consumerKey,
            consumerSecret: plugin.config.twitter.consumerSecret,
            callbackURL: `${plugin.config.publicUrl}/auth/twitter/callback`,
        };
        const twitterStrategy = new TwitterStrategy(configTwitter, registerUser);
        passport.use(twitterStrategy);
    }

    if (plugin.config.google && plugin.config.google.active) {
        debug('Loading google strategy');
        const configGoogle = {
            clientID: plugin.config.google.clientID,
            clientSecret: plugin.config.google.clientSecret,
            callbackURL: `${plugin.config.publicUrl}/auth/google/callback`,
        };
        const googleStrategy = new GoogleStrategy(configGoogle, registerUser);
        passport.use(googleStrategy);
    }

    if (plugin.config.facebook && plugin.config.facebook.active) {
        debug('Loading facebook strategy');
        const configFacebook = {
            clientID: plugin.config.facebook.clientID,
            clientSecret: plugin.config.facebook.clientSecret,
            callbackURL: `${plugin.config.publicUrl}/auth/facebook/callback`,
        };
        const facebookStrategy = new FacebookStrategy(configFacebook, registerUser);
        passport.use(facebookStrategy);
    }

}
module.exports = passportService;
