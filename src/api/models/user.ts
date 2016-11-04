import { Property, Model, Reference } from 'vulcain-corejs';
import * as crypto from 'crypto';

const saltSize = 32;

@Model({
    bind: User.bind,
    storageName: "users"
})
export class User {
    @Property({ type: "uid", isKey: true })
    id: string;
    @Property({ type: "string", unique: true, required: true })
    name: string;
    @Property({ type: "string", required: false })
    password: string;
    @Property({ type: "string", required: true })
    displayName: string;
    @Property({ type: "string" })
    email: string;
    @Property({ type: "arrayOf", item: "string" })
    scopes: Array<string>;
    @Reference({ item: "any", cardinality: "one" })
    data: any;
    @Property({ type: "boolean" })
    disabled: boolean;

    static bind(user: User) {
        if (user.password) {
            user.password = User.encryptPassword(user.password);
        }
        return user;
    }

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
