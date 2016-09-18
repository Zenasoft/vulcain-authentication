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
    EventNotificationMode,
    Model,
    Property,
    VerifyTokenParameter,
    DefaultServiceNames
} from "vulcain-corejs";
import {ApiKey} from "../models/apiKey";

@ActionHandler({async:false, scope:"token-admin",  schema:"ApiKey", serviceName:DefaultServiceNames.ApiKeyService, eventMode: EventNotificationMode.never})
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
        data.tenant = data.tenant || this.requestContext.tenant;
        return super.createAsync(data);
    }

    @Action()
    verifyTokenAsync( params: VerifyTokenParameter ) : Promise<boolean>
    {
        return new Promise( async ( resolve, reject ) =>
        {
            try
            {
                let token = await this.apis.getApiAsync(params.tenant, params.apiKey);
                if(token)
                {
                    resolve({ token: token, user: { name: token.userName, id: token.userId, tenant: token.tenant, data: token.data } });
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
    getApiAsync(tenant: string, id: string) {
        this.requestContext.tenant = tenant;
        return <Promise<ApiKey>>super.getAsync(id);
    }
}
