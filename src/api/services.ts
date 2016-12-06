import { VerifyTokenParameter, UserContext } from 'vulcain-corejs';
import { User } from './models/user';
import { ApiKey } from './models/apiKey';

export interface IApiKeyService {
    verifyTokenAsync(data: VerifyTokenParameter): Promise<boolean>;
}

export interface ITokenService {
    verifyTokenAsync(data: VerifyTokenParameter): Promise<boolean>;
    createTokenAsync(user: UserContext): Promise<string>;
}

export interface IQueryUserService {
    getUserByNameAsync(tenant: string, name: string): Promise<User>;
    verifyPassword(original, pwd): boolean;
    hasUsersAsync(tenant: string): Promise<boolean>;
}

export interface IQueryApiService {
    getApiAsync(tenant: string, id: string): Promise<ApiKey>;
}
