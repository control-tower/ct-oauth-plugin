class ApplicationDuplicated extends Error {

    constructor(message) {
        super(message);
        this.name = 'ApplicationDuplicated';
        this.message = message;
    }

}
module.exports = ApplicationDuplicated;
