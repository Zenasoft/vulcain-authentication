import { Property, Model, Reference } from 'vulcain-corejs';
import * as crypto from 'crypto';

const saltSize = 32;

export interface IUser {
    name: string;
    displayName: string;
    password: string;
    scopes: string[];
}

@Model({
    storageName: "users"
})
export class User implements IUser {
    @Property({ type:'string', isKey: true, unique: true, required: true })
    name: string;
    @Property({ type:'string',  required: false, bind: pwd => pwd && User.encryptPassword(pwd) })
    password: string;
    @Property({ type:'string', required: true, bind: (v, e) => v || e.name})
    displayName: string;
    @Property({ type: "string" })
    email: string;
    @Property({ type: "arrayOf", items: "string", required: true })
    scopes: Array<string>;
    @Reference({ item: "any", cardinality: "one" })
    disabled: boolean;

    static encryptPassword(plainText: string, salt?) {
        salt = salt && new Buffer(salt, 'hex') || crypto.randomBytes(saltSize);
        const encryptedPassword = crypto.pbkdf2Sync(plainText, salt, 2000, 64, 'sha512').toString('hex');
        return encryptedPassword + salt.toString('hex');
    }

    static verifyPassword(encryptedText: string, plainText: string) {
        const pos = encryptedText.length - (saltSize * 2);
        const salt = encryptedText.substr(pos);
        return User.encryptPassword(plainText, salt) === encryptedText;
    }
}
