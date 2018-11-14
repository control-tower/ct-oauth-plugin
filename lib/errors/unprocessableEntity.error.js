
class UnprocessableEntityError extends Error {

    constructor(message) {
        super(message);
        this.name = 'UnprocessableEntity';
        this.message = message;
        this.status = 422;
    }

}

module.exports = UnprocessableEntityError;
