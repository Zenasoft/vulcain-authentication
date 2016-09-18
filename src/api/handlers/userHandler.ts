import {Query, QueryHandler, ActionHandler, DefaultActionHandler, DefaultQueryHandler} from "vulcain-corejs";
import {User} from "../models/user";
import {IQueryUserService} from "../services";
import * as crypto from 'crypto';

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

    async getUserAsync(tenant: string, name: string) {
        this.requestContext.tenant = tenant;
        return super.getAsync(name);
    }

    async getUserByNameAsync(tenant: string, name: string) {
        this.requestContext.tenant = tenant;
        let list = await super.getAllAsync({name:name}, 2);
        return list && list.length === 1 ? list[0] : null;
    }

    async hasUsersAsync(tenant: string): Promise<boolean> {
        this.requestContext.tenant = tenant;

        let list = await super.getAllAsync({}, 1);
        return list && list.length > 0;
    }

    verifyPassword(hash, plain) {
        return hash && User.verifyPassword(hash, plain);
    }
}
