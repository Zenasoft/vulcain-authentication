
var passport = require('passport');
import passportStrategy = require('passport-strategy');
var BasicStrategy = require('passport-http').BasicStrategy;
var BearerStrategy = require('passport-http-bearer').Strategy
import {AuthenticationStrategies, Injectable, Inject, LifeTime, DefaultServiceNames, IContainer} from "vulcain-corejs";
import {IApiKeyService, ITokenService, IQueryUserService} from "./services";

@Injectable(LifeTime.Singleton)
export class Authentication
{
    constructor( @Inject( "QueryUserService", true )users:IQueryUserService, @Inject("TokenService")tokens:ITokenService, @Inject("ApiKeyService", true)apiKeys:IApiKeyService )
    {
        this.initBasic(users);
        AuthenticationStrategies.initBearer( tokens );
        AuthenticationStrategies.initApiKey( apiKeys );
    }

    private initBasic( users:IQueryUserService )
    {
        let strategy = new BasicStrategy( async ( username, password, callback ) =>
        {
            try
            {
               if(username==="admin" && password==="admin")
               {
                    // Works only on bootstrap when there is no users yet
                    let hasUsers = (users && await users.hasUsersAsync());
                    if(!hasUsers)
                    {
                        return callback(null, {id:0, name:"admin", displayName:"admin"}, {scopes:"*"});
                    }
                }

                if (!users)
                   return callback(null, false);

                let user = await users.getUserByNameAsync(username);
                // No user found with that username
                if( !user || user.disabled)
                {
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

    init() {return passport.authenticate( ['apiKey', 'bearer', 'basic'], { session: false } );}
}










