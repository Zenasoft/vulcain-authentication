import { IApiKeyService, IQueryApiService } from "../services";
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
    VerifyTokenParameter,
    DefaultServiceNames
} from "vulcain-corejs";
import { ApiKey } from "../models/apiKey";

@ActionHandler({ async: false, scope: "token:admin", schema: "ApiKey", serviceName: DefaultServiceNames.ApiKeyService, eventMode: EventNotificationMode.never })
export class ApiHandler extends DefaultActionHandler implements IApiKeyService {

    constructor(@Inject("Container") container: IContainer) {
        super(container);
    }

    createAsync(data: ApiKey) {
        data.tenant = data.tenant || this.requestContext.tenant;
        return super.createAsync(data);
    }

    @Action({ description: "Verify an api key", outputSchema: "boolean" })
    verifyTokenAsync(params: VerifyTokenParameter): Promise<boolean> {
        return new Promise(async (resolve, reject) => {
            try {
                let apis = this.container.get<IQueryApiService>("QueryApiService");
                let token = await apis.getApiAsync(params.tenant, params.token);
                if (token) {
                    resolve({ token: token, user: { name: token.userName, id: token.userId, tenant: token.tenant, data: token.data } });
                    return;
                }
                reject({ message: "Invalid api key" });
            }
            catch (err) {
                reject(err);
            }
        });
    }
}

@QueryHandler({ scope: "token:admin", schema: ApiKey, serviceName: "QueryApiService" })
class QueryApiService extends DefaultQueryHandler<ApiKey> implements IQueryApiService {
    @Query({ description: "Get an api key", action: "get" })
    getApiAsync(tenant: string, id: string) {
        this.requestContext.tenant = tenant;
        return <Promise<ApiKey>>super.getAsync(id);
    }
}
