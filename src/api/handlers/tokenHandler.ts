import { Model, Property, AbstractActionHandler, ActionHandler, Inject, Action, IAuthenticationStrategy, IContainer, EventNotificationMode, DefaultServiceNames, ConfigurationProperty, Conventions, System, DynamicConfiguration } from 'vulcain-corejs';
import { QueryUserService } from './userHandler';
import { VerifyTokenParameter } from './verifyTokenParameter';

@Model()
export class RenewData {
    @Property({ type: "string", required: true })
    renewToken: string;
}

@ActionHandler({ async: false, scope: "*", eventMode: EventNotificationMode.never })
export class TokenHandler extends AbstractActionHandler {

    @ConfigurationProperty(Conventions.instance.TOKEN_ISSUER, "string")
    private issuer: string;
    // TODO https://github.com/auth0/node-jsonwebtoken
    // Certificate file (SHA 256)
    @ConfigurationProperty(Conventions.instance.VULCAIN_SECRET_KEY, "string")
    private secretKey: string;
    @ConfigurationProperty(Conventions.instance.TOKEN_EXPIRATION, "string")
    // https://github.com/rauchg/ms.js
    private tokenExpiration: string;

    constructor(
        @Inject("Domain") domain,
        @Inject("Container") container: IContainer
    ) {
        super(container);
        this.issuer = DynamicConfiguration.getChainedConfigurationProperty<string>( Conventions.instance.TOKEN_ISSUER ).value;
        this.tokenExpiration = DynamicConfiguration.getChainedConfigurationProperty<string>(Conventions.instance.TOKEN_EXPIRATION, Conventions.instance.defaultTokenExpiration).value;
        this.secretKey = DynamicConfiguration.getChainedConfigurationProperty<string>(Conventions.instance.VULCAIN_SECRET_KEY, Conventions.instance.defaultSecretKey).value;
    }

    @Action({ description: "Renew a valid jwt token", action: "renewToken", inputSchema: "RenewData", outputSchema: "string" })
    async renewToken(data: RenewData): Promise<{ expiresIn: number, token: string, renewToken: string }> {
        let users = this.container.get<QueryUserService>("QueryUserService");
        let user = await users.getUserByName(this.context.user.tenant, this.context.user.name);
        // No user found with that username
        if (!user || user.disabled) {
            throw new Error("Invalid user");
        }

        try {
            let tokens = this.container.get<IAuthenticationStrategy>(DefaultServiceNames.AuthenticationStrategy);
            await tokens.verifyToken(this.context, data.renewToken, this.context.user.tenant);
        }
        catch (e) {
            throw new Error("Invalid renew token");
        }

        //let options = { issuer: this.issuer, expiresIn: this.tokenExpiration };

        let result = this.createToken();
        return result;
    }

    @Action({ description: "Create a new jwt token", action: "createToken", outputSchema: "string" })
    createToken(): Promise<{ expiresIn: number, token: string, renewToken: string }> {
        let ctx = this.context;
        let tokens = this.container.get<IAuthenticationStrategy>(DefaultServiceNames.BearerTokenService);
        return tokens.createToken(ctx.user);
    }
}
