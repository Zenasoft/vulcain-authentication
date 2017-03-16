import { ITokenService, IQueryUserService } from "../services";
import { VerifyTokenParameter, Model, Property, AbstractActionHandler, ActionHandler, Inject, Action, IContainer, EventNotificationMode, DefaultServiceNames, ConfigurationProperty, Conventions, System } from 'vulcain-corejs';

@Model()
export class RenewData {
    @Property({ type: "string", required: true })
    renewToken: string;
}

@ConfigurationProperty(Conventions.instance.TOKEN_ISSUER, "string")
@ConfigurationProperty(Conventions.instance.TOKEN_EXPIRATION, "string")
@ConfigurationProperty(Conventions.instance.VULCAIN_SECRET_KEY, "string")
@ActionHandler({ async: false, scope: "*", eventMode: EventNotificationMode.never })
export class TokenHandler extends AbstractActionHandler implements ITokenService {

    private issuer: string;
    // TODO https://github.com/auth0/node-jsonwebtoken
    // Certificate file (SHA 256)
    private secretKey: string;
    // https://github.com/rauchg/ms.js
    private tokenExpiration: string;

    constructor(
        @Inject("Domain") domain,
        @Inject("Container") container: IContainer
    ) {
        super(container);
        this.issuer = System.createSharedConfigurationProperty<string>( Conventions.instance.TOKEN_ISSUER ).value;
        this.tokenExpiration = System.createSharedConfigurationProperty<string>(Conventions.instance.TOKEN_EXPIRATION, Conventions.instance.defaultTokenExpiration).value;
        this.secretKey = System.createSharedConfigurationProperty<string>(Conventions.instance.VULCAIN_SECRET_KEY, Conventions.instance.defaultSecretKey).value;
    }

    @Action({ description: "Renew a valid jwt token", action: "renewToken", inputSchema: "RenewData", outputSchema: "string" })
    async renewTokenAsync(data: RenewData): Promise<string> {
        let users = this.container.get<IQueryUserService>("QueryUserService");
        let user = await users.getUserByNameAsync(this.requestContext.tenant, this.requestContext.user.name);
        // No user found with that username
        if (!user || user.disabled) {
            throw new Error("Invalid user");
        }

        try {
            await this.verifyTokenAsync({ token: data.renewToken, tenant: this.requestContext.tenant });
        }
        catch (e) {
            throw new Error("Invalid renew token");
        }

        //let options = { issuer: this.issuer, expiresIn: this.tokenExpiration };

        let result = this.createTokenAsync();
        return result;
    }

    @Action({ description: "Create a new jwt token", action: "createToken", outputSchema: "string" })
    createTokenAsync(): Promise<string> {
        let ctx = this.requestContext;
        let tokens = this.container.get<ITokenService>(DefaultServiceNames.TokenService);
        return tokens.createTokenAsync(ctx.user);
    }

    verifyTokenAsync(p: VerifyTokenParameter): Promise<any> {
        let tokens = this.container.get<ITokenService>(DefaultServiceNames.TokenService);
        return tokens.verifyTokenAsync(p);
    }
}
