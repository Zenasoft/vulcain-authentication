import { Property, Model } from 'vulcain-corejs';

@Model({ storageName: "tokens" })
export class VerifyTokenParameter {
    @Property({ type: "string", required: true })
    token: string;
    @Property({ type: "string", required: true })
    tenant: string;
}