import { VerifyTokenParameter } from 'vulcain-corejs';
import {User} from './models/user';
import {ApiKey} from './models/apiKey';

export interface IApiKeyService {
    verifyTokenAsync(data:VerifyTokenParameter): Promise<boolean>;
}

export interface ITokenService {
    verifyTokenAsync(data:VerifyTokenParameter): Promise<boolean>;
}

export interface IQueryUserService {
    getUserByNameAsync(name: string): Promise<User>;
    getUserAsync(id: string): Promise<User>;
    verifyPassword(original, pwd): boolean;
    hasUsersAsync(): Promise<boolean>;
}

export interface IQueryApiService {
    getApiAsync(id: string): Promise<ApiKey>;
}
