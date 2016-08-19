import {IApiKeyService, IQueryApiService} from "../services";
import {
    IContainer,
    Query,
    ActionHandler,
    Inject,
    Action,
    DefaultActionHandler,
    QueryHandler,
    DefaultQueryHandler,
    ActionEventMode
} from "vulcain-corejs";
import {ApiKey} from "../models/apiKey";

@ActionHandler({async:false, scope:"token-admin",  schema:"ApiKey", serviceName:"ApiKeyService", eventMode: ActionEventMode.never})
export class ApiHandler extends DefaultActionHandler implements IApiKeyService {

    constructor(
        @Inject("Container") container: IContainer,
        @Inject("QueryApiService") private apis: IQueryApiService
    )
    {
        super(container);
    }

    @Action()
    createApiKey(data: ApiKey) {
        return super.createAsync(data);
    }

    verifyTokenAsync( apiKey ) : Promise<boolean>
    {
        return new Promise( async ( resolve, reject ) =>
        {
            if(!apiKey)
            {
                reject("You must provided a valid token");
                return;
            }

            try
            {
                let token = await this.apis.getApiAsync(apiKey);
                if(token)
                {
                    resolve({token:token, user:{name:token.userName, id:token.userId, scopes:token.scopes}});
                    return;
                }
                reject({message:"Invalid api key"});
            }
            catch(err)
            {
                reject({error:err, message:"Invalid api key"});
            }
        } );
    }
}

@QueryHandler({scope:"token-admin", schema: ApiKey, serviceName: "QueryApiService"})
class QueryApiService extends DefaultQueryHandler<ApiKey> implements IQueryApiService {
    @Query({action:"get"})
    getApiAsync(id: string) {
        return <Promise<ApiKey>>super.getAsync(id);
    }
}
