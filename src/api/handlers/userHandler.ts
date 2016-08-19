import {Query, QueryHandler, ActionHandler, DefaultActionHandler, DefaultQueryHandler} from "vulcain-corejs";
import {User} from "../models/user";
import {IQueryUserService} from "../services";
const bcrypt = require('node-bcrypt');

@ActionHandler({async:false, scope:"user-admin", schema:"User", serviceName:"UserService"})
export class UserHandler extends DefaultActionHandler
{
    async validateUserAsync(user: User, action: string) {
        if (action === "create" && !user.password)
            return ["Password is required"];
    }
}

@QueryHandler({scope:"user-admin", schema: User, serviceName: "QueryUserService"})
class QueryUserService extends DefaultQueryHandler<User> {

    async getUserByNameAsync(name: string) {
        let list = await super.getAllAsync({name:name}, 2);
        return list && list.length === 1 ? list[0] : null;
    }

    async hasUsersAsync(): Promise<boolean> {
        let list = await super.getAllAsync({}, 1);
        return list && list.length > 0;
    }

    verifyPassword(hash, plain) {
        return hash && bcrypt.checkpw(plain, hash);
    }
}
