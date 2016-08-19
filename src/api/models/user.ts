import {Property, Model, Reference} from 'vulcain-corejs';
const bcrypt = require('node-bcrypt');

@Model( {
    onHttpResponse: (e: User) => { delete e.password; },
    bind: User.bind,
    storageName: "users"
})
export class User
{
    @Property({type:"uid", isKey:true})
    id:string;
    @Property({type:"string", unique:true, required:true})
    name:string;
    @Property({type:"string", required:false})
    password:string;
    @Property({type:"string", required:true})
    displayName:string;
    @Property({type:"string"})
    email:string;
    @Property({type:"arrayOf", item: "string"})
    scopes: Array<string>;
    @Reference({item:"any", cardinality:"one"})
    data: any;
    @Property({type:"boolean"})
    disabled: boolean;

    static bind(user: User) {
        if (user.password) {
            const salt = bcrypt.gensalt();
            user.password = bcrypt.hashpw(user.password, salt);
        }
        return user;
    }
}
