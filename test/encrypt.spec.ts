import { expect } from 'chai';
import {User} from '../dist/api/models/user';

const password = "^P%ls0çkdl 1&=234$€@Q";

describe("Encrypt password", function () {

    it("should create a password", () => {
        const encryptPassword = User.encryptPassword(password);
        expect(encryptPassword).to.be.not.null;
    });

    it("should verify a password", () => {
        const encryptPassword = User.encryptPassword(password);
        expect(User.verifyPassword(encryptPassword, password)).to.be.true;
    });

    it("should not validate a wrong password", () => {
        const encryptPassword = User.encryptPassword(password);
        expect(User.verifyPassword(encryptPassword, password + "x")).to.be.false;
    });

    it("should not validate a wrong encrypted password", () => {
        const encryptPassword = User.encryptPassword(password);
        expect(User.verifyPassword(encryptPassword + "x", password + "x")).to.be.false;
    });
});



