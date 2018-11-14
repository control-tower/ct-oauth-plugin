const SparkPost = require('sparkpost');
const debug = require('debug')('oauth-plugin');
const Promise = require('bluebird');

function mailService(plugin) {

    class MailService {

        constructor(sparkpostKey, publicUrl, disableEmailSending = false) {
            this.disableEmailSending = disableEmailSending;
            if (sparkpostKey) {
                this.client = new SparkPost(sparkpostKey);
            }
            this.publicUrl = publicUrl;
        }

        sendConfirmationMail(data, recipients) {
            debug('Sending confirmation mail to ', recipients);
            const reqOpts = {
                substitution_data: {
                    urlConfirm: `${this.publicUrl}/auth/confirm/${data.confirmationToken}`,
                },
                content: {
                    template_id: 'confirm-user',
                },
                recipients,
            };

            if (this.disableEmailSending) {
                debug('Email sending disabled, skipping user account confirmation email');
                debug(reqOpts);
                return new Promise(resolve => resolve());
            }

            return new Promise((resolve, reject) => {
                debug(reqOpts);
                this.client.transmissions.send(reqOpts, (error, res) => {
                    if (error) {
                        reject(error);
                    } else {
                        resolve(res);
                    }
                });
            });
        }

        sendConfirmationMailWithPassword(data, recipients) {
            debug('Sending confirmation mail to ', recipients);
            const reqOpts = {
                substitution_data: {
                    urlConfirm: `${this.publicUrl}/auth/confirm/${data.confirmationToken}?${data.callbackUrl ? `callbackUrl=${data.callbackUrl}` : ''}`,
                    password: data.password
                },
                content: {
                    template_id: 'confirm-user-with-password',
                },
                recipients,
            };

            if (this.disableEmailSending) {
                debug('Email sending disabled, skipping user account confirmation with password email');
                debug(reqOpts);
                return new Promise(resolve => resolve());
            }

            return new Promise((resolve, reject) => {
                debug(reqOpts);
                this.client.transmissions.send(reqOpts, (error, res) => {
                    if (error) {
                        reject(error);
                    } else {
                        resolve(res);
                    }
                });
            });
        }

        sendRecoverPasswordMail(data, recipients) {
            debug('Sending confirmation mail to ', recipients);
            const reqOpts = {
                substitution_data: {
                    urlRecover: `${this.publicUrl}/auth/reset-password/${data.token}`,
                },
                content: {
                    template_id: 'recover-password',
                },
                recipients,
            };

            if (this.disableEmailSending) {
                debug('Email sending disabled, skipping password recover email');
                debug(reqOpts);
                return new Promise(resolve => resolve());
            }

            return new Promise((resolve, reject) => {
                this.client.transmissions.send(reqOpts, (error, res) => {
                    if (error) {
                        reject(error);
                    } else {
                        resolve(res);
                    }
                });
            });
        }

    }

    return new MailService(plugin.config.local.sparkpostKey, plugin.config.publicUrl, plugin.config.disableEmailSending);

}

module.exports = mailService;
