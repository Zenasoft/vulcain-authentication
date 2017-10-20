import { expect } from 'chai';
import {DefaultActionHandler, DefaultQueryHandler, QueryHandler, Query, ActionHandler, Model, Property, IContainer, TestContext} from 'vulcain-corejs';

@Model()
class TestModel {
    @Property({type:"string", required: true})
    firstName: string;
    @Property({type:"string", required: true, isKey:true})
    lastName: string;
    @Property({type:"number"})
    Date: number;
}

@ActionHandler({schema: "TestModel", scope:"?"})
class TestActionHandler extends DefaultActionHandler {
}

@QueryHandler({scope:"?", schema: "TestModel", serviceName:"TestQueryService"})
class TestQueryHandler extends DefaultQueryHandler<TestModel> {
}

let context = new TestContext();

describe("Default action handler", function () {

    it("should register query handler as a service", () => {
        expect(context.container.get("TestQueryService")).to.be.not.null;
    });

    it("should create an entity", async function (done) {

        try {
            let actionHandler = context.createHandler<TestActionHandler>(TestActionHandler);
            let entity = { firstName: "elvis", lastName: "Presley" };
            await actionHandler.create(entity);

            let query = context.getService<TestQueryHandler>("TestQueryService");
            entity = await query.get("Presley");
            expect(entity).to.be.not.null;
            done();
        }
        catch (e) {
            console.log(e);
            done(e);
        }
    });

});



