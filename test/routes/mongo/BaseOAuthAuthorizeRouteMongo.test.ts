///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
// Isolated unit test for the trivial BaseOAuthAuthorizeRouteMongo model-binding class — no HTTP server, no
// database. The actual authorization logic is exercised by test/routes/BaseOAuthAuthorizeRoute.test.ts; this
// only confirms the Mongo model classes are wired in correctly.
import { AuthorizationCodeMongo, ClientMongo, ConsentGrantMongo } from "../../../src/mongo.js";
import { BaseOAuthAuthorizeRouteMongo } from "../../../src/routes/mongo/BaseOAuthAuthorizeRouteMongo.js";

class TestOAuthAuthorizeRouteMongo extends BaseOAuthAuthorizeRouteMongo {
    protected resourceOwnerStrategies: string[] = ["jwt"];
}

describe("BaseOAuthAuthorizeRouteMongo Tests", () => {
    it("Binds the Mongo Client/AuthorizationCode/ConsentGrant model classes.", () => {
        const route = new TestOAuthAuthorizeRouteMongo();

        expect((route as any).clientClass).toBe(ClientMongo);
        expect((route as any).authorizationCodeClass).toBe(AuthorizationCodeMongo);
        expect((route as any).consentGrantClass).toBe(ConsentGrantMongo);
    });
});
