class UserNotFound extends Error {

    constructor(message) {
        super(message);
        this.name = 'UserNotFound';
        this.message = message;
    }

}
module.exports = UserNotFound;
