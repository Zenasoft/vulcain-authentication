
var passport = require('passport');
var BasicStrategy = require('passport-http').BasicStrategy;
import { System, RequestContext, AuthenticationStrategies, Inject } from "vulcain-corejs";
import { IApiKeyService, IQueryUserService } from "./services";

export class UsersAuthentication {
    constructor( @Inject("ApiKeyService", true) apiKeys: IApiKeyService) {
        this.initBasic();
        AuthenticationStrategies.initBearer();
        if (apiKeys) {
            AuthenticationStrategies.initApiKey();
        }
        AuthenticationStrategies.initAnonymous();
    }

    private initBasic() {
        let strategy = new BasicStrategy({ passReqToCallback: true }, async (req, username, password, callback) => {
            let ctx = <RequestContext>req.requestContext;

            try {
                let users = ctx.container.get<IQueryUserService>("QueryUserService");

                if (username === "admin" && password === "admin") {
                    // Works only on bootstrap when there is no users yet
                    let hasUsers = (users && await users.hasUsersAsync(ctx.tenant));
                    if (!hasUsers) {
                        System.log.info(ctx, `User authentication: Connected with default admin profile`);
                        return callback(null, { id: 0, name: "admin", displayName: "admin", scopes: "*" });
                    }
                }

                if (!users) {
                    return callback(null, false);
                }

                let user = await users.getUserByNameAsync(ctx.tenant, username);
                // No user found with that username
                if (!user || user.disabled) {
                    System.log.info(ctx, `User authentication: Invalid profile ${username} tenant ${ctx.tenant}`);
                    return callback(null, false);
                }

                // Make sure the password is correct
                let isMatch = users.verifyPassword(user.password, password);

                // Password did not match
                if (!isMatch) {
                    System.log.info(ctx, `User authentication: Invalid password for ${username} tenant ${ctx.tenant}`);
                    return callback(null, false);
                }

                // Success
                return callback(null, user);
            }
            catch (err) {
                System.log.error(ctx, err, `User authentication: Error for profile ${username} tenant ${ctx.tenant}`);
                return callback(err, false);
            }
        });
        // Workaround to remove Basic realm header to avoid a browser popup
        strategy._challenge = () => null;

        passport.use(strategy);
    }

    init() { return passport.authenticate(['apiKey', 'bearer', 'basic', 'anonymous'], { session: false }); }
}










