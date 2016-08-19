import {Authentication} from './api/expressAuthentication';
import * as Path from 'path';

export {User} from './api/models/user';
export {ApiKey} from './api/models/apiKey';

export function useUserManagement(container) {
    let path = Path.dirname(module.filename);
    container.injectFrom(Path.join(path, 'api/handlers'));
    container.injectSingleton(Authentication, "Authentication");
}