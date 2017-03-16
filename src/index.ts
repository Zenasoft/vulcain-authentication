import { DefaultServiceNames, IContainer } from 'vulcain-corejs';
import { UsersAuthentication } from './api/expressAuthentication';
import * as Path from 'path';
export { User, IUser } from './api/models/user';
export { ApiKey } from './api/models/apiKey';

export function useUserManagement(container: IContainer) {
    let path = Path.dirname(module.filename);
    container.injectFrom(Path.join(path, 'api/handlers'));
    // Replace existing service
    container.injectSingleton(UsersAuthentication, DefaultServiceNames.Authentication);
}