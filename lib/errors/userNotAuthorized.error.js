class UserNotAuthorized extends Error {

    constructor(message) {
        super(message);
        this.name = 'UserNotAuthorized';
        this.message = message;
    }

}
module.exports = UserNotAuthorized;
