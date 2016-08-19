
var passport = require('passport');
import passportStrategy = require('passport-strategy');
var BasicStrategy = require('passport-http').BasicStrategy;
var BearerStrategy = require('passport-http-bearer').Strategy
import {Injectable, Inject, LifeTime, DefaultServiceNames, IContainer} from "vulcain-corejs";
import {IApiKeyService, ITokenService, IQueryUserService} from "./services";

@Injectable(LifeTime.Singleton)
export class Authentication
{
    constructor( @Inject( "QueryUserService", true )users:IQueryUserService, @Inject("TokenService")tokens:ITokenService, @Inject("ApiKeyService", true)apiKeys:IApiKeyService )
    {
        this.initBasic(users);
        this.initBearer( tokens );
        this.initApiKey( apiKeys );
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

    private initBearer( tokens:ITokenService )
    {
        let strategy = new BearerStrategy( async ( accessToken, callback ) =>
        {
            try
            {
                let token = await (<any>tokens).verifyTokenAsync(accessToken );

                // No token found
                if( !token )
                {
                    return callback( null, false );
                }

                token.user.scopes= token.scopes
                callback(null, token.user);
            }
            catch( err )
            {
                return callback( null, false );
            }
        });

        // Workaround to remove Basic realm header to avoid a browser popup
        strategy._challenge = ()=>null;

        passport.use( strategy );
    }

    private initApiKey( apiKeys:IApiKeyService )
    {
        let strategy = new ApiKeyStrategy( async ( apiKey, callback ) =>
        {
            try
            {
                let token = await (<any>apiKeys).verifyTokenAsync(apiKey );

                // No token found
                if( !token )
                {
                    return callback( null, false );
                }

                token.user.scopes = Array.isArray(token.token.scopes) ? token.token.scopes : [<string>token.token.scopes];
                callback(null, token.user);
            }
            catch( err )
            {
                return callback( null, false );
            }
        });

        passport.use( strategy );
    }
    init() {return passport.authenticate( ['apiKey', 'bearer', 'basic'], { session: false } );}
}

class ApiKeyStrategy extends passportStrategy.Strategy {

    name: string;
    private _verify: Function;
    private _passReqToCallback: boolean;

  constructor(options: any, verify?: Function)
  {
        if (typeof options == 'function') {
            verify = options;
            options = {};
        }
        if (!verify) {
            throw new TypeError('ApiKeyStrategy requires a verify callback');
        }

        super();

        this.name = 'apiKey';
        this._verify = verify;
        this._passReqToCallback = options.passReqToCallback;
    }

    /**
     * Authenticate request based on the contents of a HTTP Basic authorization
     * header.
     *
     * @param {Object} req
     * @api protected
     */
    authenticate(req) {
        var authorization = req.headers['authorization'];
        if (!authorization) { return this.success(false, null); }

        var parts = authorization.split(' ')
        if (parts.length < 2) { return this.fail(400); }

        var scheme = parts[0]
        , apiKey = parts[1];

        if (!/ApiKey/i.test(scheme)) { return this.fail(null); }
        if (!apiKey) { return this.fail(null); }

        var self = this;

        function verified(err, user, info) {
            if (err) { return self.error(err); }
            if (!user) { return self.fail(null); }
            self.success(user, info);
        }

        if (self._passReqToCallback) {
            this._verify(req, apiKey, verified);
        } else {
            this._verify(apiKey, verified);
        }
    }
}








