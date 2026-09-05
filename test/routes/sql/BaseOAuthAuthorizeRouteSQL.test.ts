///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
// Isolated unit test for the trivial BaseOAuthAuthorizeRouteSQL model-binding class — no HTTP server, no
// database. The actual authorization logic is exercised by test/routes/BaseOAuthAuthorizeRoute.test.ts; this
// only confirms the SQL model classes are wired in correctly.
import { AuthorizationCodeSQL, ClientSQL, ConsentGrantSQL } from "../../../src/sql.js";
import { BaseOAuthAuthorizeRouteSQL } from "../../../src/routes/sql/BaseOAuthAuthorizeRouteSQL.js";

class TestOAuthAuthorizeRouteSQL extends BaseOAuthAuthorizeRouteSQL {
    protected resourceOwnerStrategies: string[] = ["jwt"];
}

describe("BaseOAuthAuthorizeRouteSQL Tests", () => {
    it("Binds the SQL Client/AuthorizationCode/ConsentGrant model classes.", () => {
        const route = new TestOAuthAuthorizeRouteSQL();

        expect((route as any).clientClass).toBe(ClientSQL);
        expect((route as any).authorizationCodeClass).toBe(AuthorizationCodeSQL);
        expect((route as any).consentGrantClass).toBe(ConsentGrantSQL);
    });
});
