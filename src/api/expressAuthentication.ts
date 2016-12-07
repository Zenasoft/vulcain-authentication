import { ExpressAuthentication, System, RequestContext, Inject } from "vulcain-corejs";
import { IApiKeyService, IQueryUserService } from "./services";

export class UsersAuthentication extends ExpressAuthentication {

    constructor() {
        super();
        this.addOrReplaceStrategy("basic", this.basicAuthentication);
    }

    private async basicAuthentication(ctx: RequestContext, token: string) {
        let username: string;
        let password: string;
        try {
            let users = ctx.container.get<IQueryUserService>("QueryUserService");
            let credentials = new Buffer(token, 'base64').toString().split(':');
            username = credentials[0];
            password = credentials[1];
            if (!username || !password) {
                return null;
            }
            if (username === "admin" && password === "admin") {
                // Works only on bootstrap when there is no users yet
                let hasUsers = (users && await users.hasUsersAsync(ctx.tenant));
                if (!hasUsers) {
                    System.log.info(ctx, `User authentication: Connected with default admin profile`);
                    return { id: 0, name: "admin", displayName: "admin", scopes: "*" };
                }
            }

            if (!users) {
                return null;
            }

            let user = await users.getUserByNameAsync(ctx.tenant, username);
            // No user found with that username
            if (!user || user.disabled) {
                System.log.info(ctx, `User authentication: Invalid profile ${username} tenant ${ctx.tenant}`);
                return null;
            }

            // Make sure the password is correct
            let isMatch = users.verifyPassword(user.password, password);

            // Password did not match
            if (!isMatch) {
                System.log.info(ctx, `User authentication: Invalid password for ${username} tenant ${ctx.tenant}`);
                return null;
            }

            // Success
            return user;
        }
        catch (err) {
            System.log.error(ctx, err, `User authentication: Error for profile ${username} tenant ${ctx.tenant}`);
            return null;
        }
    }
}