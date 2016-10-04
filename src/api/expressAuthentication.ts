
var passport = require('passport');
import passportStrategy = require('passport-strategy');
var BasicStrategy = require('passport-http').BasicStrategy;
var BearerStrategy = require('passport-http-bearer').Strategy
import {Conventions, RequestContext, AuthenticationStrategies, Injectable, Inject, LifeTime, DefaultServiceNames, IContainer} from "vulcain-corejs";
import {IApiKeyService, ITokenService, IQueryUserService} from "./services";

export class UsersAuthentication
{
    constructor( @Inject( "QueryUserService", true )users:IQueryUserService, @Inject("TokenService")tokens:ITokenService, @Inject("ApiKeyService", true)apiKeys:IApiKeyService )
    {
        this.initBasic(users);
        AuthenticationStrategies.initBearer( tokens );
        AuthenticationStrategies.initApiKey(apiKeys);
        AuthenticationStrategies.initAnonymous();
    }

    private initBasic( users:IQueryUserService )
    {
        let strategy = new BasicStrategy( {passReqToCallback:true}, async ( req, username, password, callback ) =>
        {
            try
            {
                let tenant = req.headers["X_VULCAIN_TENANT"] || process.env[Conventions.instance.ENV_TENANT] || RequestContext.TestTenant;

               if(username==="admin" && password==="admin")
               {
                    // Works only on bootstrap when there is no users yet
                    let hasUsers = (users && await users.hasUsersAsync(tenant));
                    if(!hasUsers)
                    {
                        return callback(null, {id:0, name:"admin", displayName:"admin", scopes:"*"});
                    }
                }

                if (!users)
                   return callback(null, false);

                let user = await users.getUserByNameAsync(tenant, username);
                // No user found with that username
                if( !user || user.disabled)
                {
                    console.log("LOGIN: invalid user name " + username + " for tenant " + tenant);
                    return callback( null, false );
                }

                // Make sure the password is correct
                let isMatch = users.verifyPassword( user.password, password );

                // Password did not match
                if( !isMatch )
                {
                    return callback( null, false );
                }

                // Success
                return callback( null, user );
            }
            catch( err )
            {
                return callback( err, false );
            }
        });
        // Workaround to remove Basic realm header to avoid a browser popup
        strategy._challenge = ()=>null;

        passport.use( strategy );
    }

    init() {return passport.authenticate( ['apiKey', 'bearer', 'basic', 'anonymous'], { session: false } );}
}










