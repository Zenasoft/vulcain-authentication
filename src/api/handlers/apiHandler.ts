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
    DefaultServiceNames
} from "vulcain-corejs";
import { ApiKey } from "../models/apiKey";
import sanitize from 'mongo-sanitize';
import { VerifyTokenParameter } from "./verifyTokenParameter";

@ActionHandler({ async: false, scope: "token:admin", schema: "ApiKey", eventMode: EventNotificationMode.never })
export class ApiHandler extends DefaultActionHandler {

    constructor(@Inject("Container") container: IContainer) {
        super(container);
    }

    create(data: ApiKey) {
        data.tenant = data.tenant || this.context.user.tenant;
        return super.create(data);
    }

    @Action({ description: "Verify an api key", outputSchema: "boolean" })
    verifyToken(params: VerifyTokenParameter): Promise<boolean> {
        return new Promise(async (resolve, reject) => {
            try {
                let apis = this.container.get<QueryApiService>("QueryApiService");
                let token = await apis.getApi(params.tenant, params.token);
                resolve(!!token);
            }
            catch (err) {
                resolve(false);
            }
        });
    }
}

@QueryHandler({ scope: "token:admin", schema: "ApiKey", serviceName: "QueryApiService" })
class QueryApiService extends DefaultQueryHandler<ApiKey> {
    @Query({ description: "Get an api key", action: "get" })
    getApi(tenant: string, id: string) {
        this.context.user.tenant = tenant;
        return <Promise<ApiKey>>super.get(sanitize(id));
    }
}
