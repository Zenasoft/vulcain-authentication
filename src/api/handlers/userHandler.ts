import { QueryHandler, ActionHandler, DefaultActionHandler, DefaultQueryHandler } from "vulcain-corejs";
import { User } from "../models/user";
import sanitize from 'mongo-sanitize';

@ActionHandler({ async: false, scope: "user:admin", schema: "User", serviceName: "UserService" })
export class UserHandler extends DefaultActionHandler {
    async validateUserAsync(user: User, action: string) {
        if (action === "create" && !user.password) {
            return ["Password is required"];
        }
    }
}

@QueryHandler({ scope: "user:admin", schema: "User", serviceName: "QueryUserService" })
export class QueryUserService extends DefaultQueryHandler<User> {

    async getAsync(name: string) {

        let user = await super.getAsync(sanitize(name));
        if (user) {
            user.password = undefined;
        }
        return user;
    }

    async getUserByNameAsync(tenant: string, name: string) {
        let t = this.context.user.tenant;
        try {
            this.context.user.tenant = tenant;
            let list = await super.getAllAsync({ name: sanitize(name) }, 2);
            return list && list.length === 1 ? list[0] : null;
        }
        finally {
            this.context.user.tenant = t;
        }
    }

    async hasUsersAsync(tenant: string): Promise<boolean> {
        let t = this.context.user.tenant;
        try {
            this.context.user.tenant = tenant;
            let list = await super.getAllAsync({}, 1);
            return list && list.length > 0;
        }
        finally {
            this.context.user.tenant = t;
        }
    }

    verifyPassword(hash, plain) {
        return hash && User.verifyPassword(hash, plain);
    }
}
