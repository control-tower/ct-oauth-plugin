const CONTROL_TOWER = 'control-tower';

class Utils {

    static isCTAdmin(user) {
        if (user.roles) {
            for (let i = 0, length = user.roles.length; i < length; i++) {
                if (user.roles[i].name === CONTROL_TOWER && user.roles[i].role === 'ADMIN') {
                    return true;
                }
            }
        }
        return false;
    }

    static isCTManager(user) {
        if (user.roles) {
            for (let i = 0, length = user.roles.length; i < length; i++) {
                if (user.roles[i].name === CONTROL_TOWER && user.roles[i].role === 'MANAGER') {
                    return true;
                }
            }
        }
        return false;
    }

    static isCTRoles(user, roles) {
        if (user.roles) {
            for (let i = 0, length = user.roles.length; i < length; i++) {
                if (user.roles[i].name === CONTROL_TOWER && roles.indexOf(user.roles[i].role) >= 0) {
                    return true;
                }
            }
        }
        return false;
    }

}

module.exports = Utils;
