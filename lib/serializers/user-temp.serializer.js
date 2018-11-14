/* eslint-disable no-underscore-dangle */

class UserTempSerializer {

    static serializeElement(el) {
        return {
            id: el._id,
            email: el.email,
            createdAt: el.createdAt,
            role: el.role,
            extraUserData: el.extraUserData
        };
    }

    static serialize(data) {
        const result = {};
        if (data && Array.isArray(data) && data.length === 0) {
            result.data = [];
            return result;
        }
        if (data) {
            if (Array.isArray(data)) {
                result.data = UserTempSerializer.serializeElement(data[0]);
            } else {
                result.data = UserTempSerializer.serializeElement(data);
            }
        }
        return result;
    }

}

module.exports = UserTempSerializer;
