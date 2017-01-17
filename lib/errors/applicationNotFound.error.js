class ApplicationNotAuthorized extends Error {

    constructor(message) {
        super(message);
        this.name = 'ApplicationNotAuthorized';
        this.message = message;
    }

}
module.exports = ApplicationNotAuthorized;
